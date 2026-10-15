"""Collect bounded evidence without turning weak indicators into a verdict."""

import asyncio
import hashlib
import json
import ssl
import time
from dataclasses import asdict
from datetime import UTC, datetime
from urllib.parse import urljoin

import aiohttp
import dns.exception
import dns.resolver
from cryptography import x509
from yarl import URL

from .content import extract_page
from .target import InvalidTarget, parse_target
from .transport import PublicResolver, read_bounded, session_for

MAX_BODY = 131072
MAX_HOPS = 4
REDIRECTS = {301, 302, 303, 307, 308}


def now():
    return datetime.now(UTC).isoformat()


def evidence(identifier, label, status, data=None, note=""):
    return dict(id=identifier, label=label, status=status, collected_at=now(), data=data, note=note)


async def probe_dns_policy(target, resolver):
    if target.is_ip:
        return evidence(
            "dns_policy",
            "DNS / e-posta politikaları",
            "not_run",
            note="IP adresinde alan adı politikası sorgulanmaz.",
        )
    domain = target.registrable_domain or target.host
    queries = [(target.host, "CAA"), (domain, "MX"), (domain, "TXT"), ("_dmarc." + domain, "TXT")]

    async def query(name, kind):
        try:
            answer = await resolver.resolver.resolve(name, kind, lifetime=2.5, search=False)
            values = [item.to_text()[:1024] for item in answer][:20]
            if kind == "TXT":
                values = [
                    b"".join(item.strings).decode("utf-8", errors="replace")[:1024]
                    for item in list(answer)[:20]
                    if b"".join(item.strings).lower().startswith((b"v=spf1", b"v=dmarc1"))
                ]
            return dict(
                name=name, type=kind, status="observed" if values else "no_record", records=values
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return dict(name=name, type=kind, status="no_record", records=[])
        except dns.exception.DNSException:
            return dict(name=name, type=kind, status="unavailable", records=[])

    async with asyncio.timeout(3):
        data = await asyncio.gather(*(query(name, kind) for name, kind in queries))
    return evidence(
        "dns_policy",
        "DNS / e-posta politikaları",
        "unavailable" if any(item["status"] == "unavailable" for item in data) else "observed",
        data,
        "Yayımlanan MX, SPF/DMARC ve CAA kayıtlarıdır. SPF zinciri, DMARC hizalaması, CAA kalıtımı ve DNSSEC doğrulanmaz; kayıt yokluğu phishing kanıtı değildir.",
    )


async def probe_tls(target, resolver):
    writer = None
    try:
        async with asyncio.timeout(3):
            addresses = await resolver.addresses(target.host)
            _reader, writer = await asyncio.open_connection(
                addresses[0],
                443,
                ssl=ssl.create_default_context(),
                server_hostname=target.host,
                ssl_handshake_timeout=2,
            )
            secure = writer.get_extra_info("ssl_object")
            der = secure.getpeercert(binary_form=True)
            certificate = x509.load_der_x509_certificate(der)
            try:
                names = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                names = []
            data = dict(
                host=target.host,
                port=443,
                connected_ip=addresses[0],
                tls_version=secure.version(),
                cipher=secure.cipher()[0],
                certificate_sha256=hashlib.sha256(der).hexdigest(),
                subject=certificate.subject.rfc4514_string(),
                issuer=certificate.issuer.rfc4514_string(),
                valid_from=certificate.not_valid_before_utc.isoformat(),
                valid_until=certificate.not_valid_after_utc.isoformat(),
                dns_names=names[:100],
                verification="system_trust_store_and_hostname",
            )
            return evidence(
                "tls",
                "TLS sertifikası",
                "observed",
                data,
                "Sertifika alan adı ve sistem güven deposuyla doğrulandı. Site sahibinin niyetini veya sayfanın güvenliğini kanıtlamaz.",
            )
    except ssl.SSLCertVerificationError as error:
        return evidence(
            "tls",
            "TLS sertifikası",
            "verification_failed",
            {"code": error.verify_code},
            "Sertifika doğrulaması başarısız. Doğrulama devre dışı bırakılmadı.",
        )
    except (OSError, TimeoutError, ssl.SSLError):
        return evidence(
            "tls",
            "TLS sertifikası",
            "unavailable",
            note="TLS bağlantısı kurulamadı veya süresi doldu.",
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
            except (OSError, TimeoutError, ssl.SSLError):
                pass


async def probe_http(target, resolver, session, report, max_hops=MAX_HOPS):
    current = target
    seen = set()
    trail = []
    try:
        for index in range(max_hops + 1):
            if current.url in seen:
                report["evidence"].append(
                    evidence(
                        "http",
                        "HTTP zinciri",
                        "limited",
                        trail,
                        "Yönlendirme döngüsü nedeniyle durduruldu.",
                    )
                )
                return
            seen.add(current.url)
            addresses = await resolver.addresses(current.host)
            async with session.get(
                URL(current.url, encoded=True), allow_redirects=False
            ) as response:
                selected = {
                    key.lower(): response.headers[key][:2048]
                    for key in (
                        "Content-Type",
                        "Content-Encoding",
                        "Content-Security-Policy",
                        "Strict-Transport-Security",
                        "X-Content-Type-Options",
                        "X-Frame-Options",
                        "Referrer-Policy",
                        "Location",
                    )
                    if key in response.headers
                }
                hop = dict(
                    url=current.url,
                    serialized_request_url=str(response.url),
                    status=response.status,
                    resolved_addresses=addresses,
                    headers=selected,
                    collected_at=now(),
                )
                trail.append(hop)
                if response.status in REDIRECTS and response.headers.get("Location"):
                    if index == max_hops:
                        report["evidence"].append(
                            evidence(
                                "http",
                                "HTTP zinciri",
                                "limited",
                                trail,
                                "Yönlendirme sınırına ulaşıldı.",
                            )
                        )
                        return
                    following = parse_target(urljoin(current.url, response.headers["Location"]))
                    if current.scheme == "https" and following.scheme == "http":
                        report["findings"].append(
                            dict(
                                kind="https_downgrade",
                                detail="Sunucu HTTPS'den HTTP'ye yönlendirme döndürdü.",
                                evidence={"from": current.url, "to": following.url},
                            )
                        )
                    current = following
                    continue
                # No response cookies are retained and no script/subresource is fetched.
                data, truncated = await read_bounded(response, MAX_BODY)
                hop.update(
                    dict(
                        body_bytes_collected=len(data),
                        body_sha256=hashlib.sha256(data).hexdigest(),
                        body_truncated=truncated,
                    )
                )
                if selected.get("content-encoding", "identity").lower() not in ("", "identity"):
                    hop["content_analysis"] = "not_run_encoded_body"
                    truncated = True
                elif "text/html" in selected.get("content-type", "").lower():
                    page, findings = extract_page(
                        data, current.url, transport_encoding=response.charset, truncated=truncated
                    )
                    hop["page"] = page
                    report["findings"].extend(findings)
                    truncated = truncated or page["limited"]
                else:
                    hop["content_analysis"] = "not_html"
                report["evidence"].append(
                    evidence(
                        "http",
                        "HTTP zinciri",
                        "limited" if truncated else "observed",
                        trail,
                        "En fazla 128 KiB içerik incelendi; JavaScript çalıştırılmadı. Kullanıcı etkileşimleri ve tarayıcıya göre farklı sunulan içerik kapsam dışı.",
                    )
                )
                return
    except asyncio.CancelledError:
        report["evidence"].append(
            evidence(
                "http",
                "HTTP zinciri",
                "limited",
                trail,
                "Toplam süre doldu; yalnızca tamamlanan HTTP başlıkları ve yönlendirmeler kaydedildi.",
            )
        )
        raise
    except InvalidTarget:
        report["evidence"].append(
            evidence(
                "http",
                "HTTP zinciri",
                "blocked",
                trail,
                "Bir yönlendirme veya DNS yanıtı hedef politikasını ihlal etti; sonraki bağlantı engellendi.",
            )
        )
    except (aiohttp.ClientError, OSError, TimeoutError, ValueError):
        report["evidence"].append(
            evidence(
                "http",
                "HTTP zinciri",
                "unavailable",
                trail,
                "İstek tamamlanamadı. Ağ hatası temiz sonuç değildir.",
            )
        )


def validate_threat_response(data, target):
    if not isinstance(data, dict) or "error" in data:
        raise ValueError("Invalid provider payload")
    matches = data.get("matches", [])
    if not isinstance(matches, list) or len(matches) > 100:
        raise ValueError("Invalid matches")
    accepted = []
    for match in matches:
        if not isinstance(match, dict) or match.get("threatType") not in {
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
        }:
            raise ValueError("Invalid threat type")
        if parse_target(match.get("threat", {}).get("url")).url != target.url:
            raise ValueError("Provider match refers to a different URL")
        accepted.append(
            dict(
                threat_type=match["threatType"],
                url=target.url,
                cache_duration=match.get("cacheDuration"),
            )
        )
    return accepted


async def probe_threats(target, api_key, session):
    if not api_key or api_key.startswith("YOUR_"):
        return evidence(
            "threat_lists",
            "Google Safe Browsing",
            "not_configured",
            note="API anahtarı yok; bu kaynak sorgulanmadı.",
        )
    payload = {
        "client": {"clientId": "t3-inspector", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target.url}],
        },
    }
    try:
        async with session.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": api_key},
            json=payload,
            allow_redirects=False,
        ) as response:
            if response.status != 200:
                raise ValueError("Provider HTTP failure")
            data, truncated = await read_bounded(response, MAX_BODY)
            if truncated:
                raise ValueError("Oversized provider response")
            matches = validate_threat_response(json.loads(data), target)
        return evidence(
            "threat_lists",
            "Google Safe Browsing",
            "matched" if matches else "no_match",
            {"provider": "Google Safe Browsing v4", "queried_url": target.url, "matches": matches},
            "Kaynağın bu anda verdiği yanıttır; bağımsız doğrulama veya güvenlik garantisi değildir.",
        )
    except (aiohttp.ClientError, OSError, TimeoutError, ValueError, TypeError, AttributeError):
        return evidence(
            "threat_lists",
            "Google Safe Browsing",
            "unavailable",
            note="Sağlayıcı yanıtı alınamadı veya doğrulanamadı. Eşleşme yok sonucu verilemez.",
        )


async def inspect_url(
    value, *, active=False, threat_lookup=False, api_key="", timeout=12, max_hops=MAX_HOPS
):
    start = time.perf_counter()
    target = parse_target(value)
    report = dict(
        schema="t3-evidence/1",
        target=asdict(target),
        started_at=now(),
        evidence=[],
        findings=[],
        conclusion="no_safety_verdict",
        scope={
            "active": active,
            "threat_lookup": threat_lookup,
            "deadline_seconds": timeout,
            "max_redirects": max_hops,
            "max_body_bytes": MAX_BODY,
        },
    )
    report["evidence"].append(
        evidence(
            "url",
            "URL yapısı",
            "observed",
            {
                "ascii_host": target.host,
                "unicode_host": target.display_host,
                "registrable_domain": target.registrable_domain,
                "scheme": target.scheme,
                "ip_literal": target.is_ip,
                "fragment_removed": "#" in value,
            },
            "Alan adı, HTTPS, uzunluk veya Unicode kullanımı tek başına phishing kararı verdirmez. Genel son ek listesi paket içi anlık görüntüsüdür.",
        )
    )
    resolver = PublicResolver()
    requested = {}
    if active:
        requested.update(
            dns="DNS adresleri",
            tls="TLS sertifikası",
            dns_policy="DNS / e-posta politikaları",
            http="HTTP zinciri",
        )
    if threat_lookup:
        requested["threat_lists"] = "Google Safe Browsing"

    async def collect(identifier, operation):
        try:
            item = await operation()
            if item is not None:
                report["evidence"].append(item)
        except InvalidTarget:
            report["evidence"].append(
                evidence(
                    identifier,
                    requested[identifier],
                    "blocked",
                    note="Hedef veya DNS yanıtı bağlantı politikasını ihlal etti.",
                )
            )
        except (OSError, aiohttp.ClientError, dns.exception.DNSException, TimeoutError):
            report["evidence"].append(
                evidence(
                    identifier,
                    requested[identifier],
                    "unavailable",
                    note="Bu kontrol tamamlanamadı; temiz sonuç değildir.",
                )
            )

    async def dns_addresses():
        addresses = await resolver.addresses(target.host)
        return evidence(
            "dns",
            "DNS adresleri",
            "observed",
            {"host": target.host, "addresses": addresses},
            "Sistem DNS çözümleyicisinin yanıtı; DNSSEC doğrulanmadı. Bağlantılar rapor süresince bu adreslere sabitlenir.",
        )

    try:
        async with asyncio.timeout(timeout):
            if active or threat_lookup:
                async with session_for(resolver) as session:
                    tasks = []
                    if active:
                        tasks.extend(
                            (
                                collect("dns", dns_addresses),
                                collect("tls", lambda: probe_tls(target, resolver)),
                                collect("dns_policy", lambda: probe_dns_policy(target, resolver)),
                                collect(
                                    "http",
                                    lambda: probe_http(target, resolver, session, report, max_hops),
                                ),
                            )
                        )
                    if threat_lookup:
                        tasks.append(
                            collect("threat_lists", lambda: probe_threats(target, api_key, session))
                        )
                    await asyncio.gather(*tasks)
            if not active:
                report["evidence"].append(
                    evidence(
                        "network",
                        "Hedef sunucu kontrolleri",
                        "not_run",
                        note="Pasif mod; hedefe bağlantı kurulmadı.",
                    )
                )
            if not threat_lookup:
                report["evidence"].append(
                    evidence(
                        "threat_lists",
                        "Tehdit kaynağı",
                        "not_run",
                        note="Üçüncü tarafa URL gönderimi istenmedi.",
                    )
                )
    except TimeoutError:
        report["evidence"].append(
            evidence(
                "deadline",
                "Toplam süre sınırı",
                "limited",
                note="Toplam süre doldu; bekleyen ağ işlemleri iptal edildi.",
            )
        )
    except (OSError, aiohttp.ClientError):
        report["evidence"].append(
            evidence(
                "network", "Ağ kontrolleri", "unavailable", note="DNS/ağ kontrolü tamamlanamadı."
            )
        )
    present = {item["id"] for item in report["evidence"]}
    for identifier, label in requested.items():
        if identifier not in present:
            report["evidence"].append(
                evidence(
                    identifier,
                    label,
                    "unavailable",
                    note="Toplam süre veya ağ hatası nedeniyle bu kontrol tamamlanamadı.",
                )
            )
    report["evidence"].sort(key=lambda item: item["id"])
    report["partial"] = any(
        item["status"] in {"unavailable", "limited", "blocked", "not_configured"}
        for item in report["evidence"]
    )
    if any(item["status"] == "matched" for item in report["evidence"]):
        report["conclusion"] = "threat_source_match"
    report["finished_at"] = now()
    report["duration_ms"] = round((time.perf_counter() - start) * 1000)
    report["limitations"] = [
        "Güvenli/zararlı olma olasılığı veya kesin phishing kararı hesaplanmaz.",
        "İçerik hedefin bu istemciye bu anda sunduğu sınırlı yanıttır; değiştirilebilir veya gizlenebilir.",
        "JavaScript, tarayıcı etkileşimi, indirmeler, sandbox davranışı ve marka sahipliği doğrulanmaz.",
        "Sertifika ve DNS bulguları kimlik/niyet kanıtı değildir. Tehdit listeleri hatalı veya gecikmeli olabilir.",
    ]
    return report
