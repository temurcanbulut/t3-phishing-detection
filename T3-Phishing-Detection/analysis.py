"""Explainable URL signals, explicit unknown states and public-only probes."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import urlsplit, urlunsplit

import requests

TIMEOUT = 4


class InvalidTarget(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    url: str
    host: str
    is_ip: bool


def parse_target(value):
    if not isinstance(value, str) or not value.strip():
        raise InvalidTarget("Analiz etmek için bir bağlantı girin.")
    value = value.strip()
    if len(value) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise InvalidTarget(
            "URL çok uzun ya da geçersiz boşluk/kontrol karakterleri içeriyor."
        )
    if "\\" in value:
        raise InvalidTarget("URL içinde ters eğik çizgi kullanılamaz.")
    candidate = value if "://" in value else "https://" + value
    try:
        parts = urlsplit(candidate)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError
        if parts.username is not None or parts.password is not None:
            raise InvalidTarget(
                "Kullanıcı adı veya parola içeren URL'ler desteklenmiyor."
            )
        if parts.port not in (None, 80 if parts.scheme == "http" else 443):
            raise InvalidTarget(
                "Yalnızca standart HTTP ve HTTPS bağlantıları destekleniyor."
            )
        host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
            labels = host.split(".")
            if (
                len(host) > 253
                or len(labels) < 2
                or not all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in labels
                )
            ):
                raise ValueError
        authority = f"[{host}]" if ":" in host else host
        return Target(
            urlunsplit((parts.scheme, authority, parts.path or "/", parts.query, "")),
            host,
            is_ip,
        )
    except InvalidTarget:
        raise
    except (ValueError, UnicodeError):
        raise InvalidTarget(
            "Geçerli bir HTTP/HTTPS URL'si veya alan adı girin."
        ) from None


def is_public(address):
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public(host):
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise InvalidTarget(
            "Alan adı çözümlenemedi. Yazımını ve ağ bağlantısını kontrol edin."
        ) from None
    addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
    if not addresses or not all(is_public(address) for address in addresses):
        raise InvalidTarget("Yerel, özel veya ayrılmış ağ adresleri analiz edilemez.")
    return addresses[0]


def check(key, label, status, detail, points=0):
    return dict(id=key, label=label, status=status, detail=detail, points=points)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Pin the checked DNS result while preserving TLS SNI and hostname checks."""

    def __init__(self, host, address):
        super().__init__(host, timeout=TIMEOUT, context=ssl.create_default_context())
        self._create_connection = (
            lambda _target, timeout, source_address: socket.create_connection(
                (address, 443), timeout, source_address
            )
        )


def inspect_https(target, address):
    connection = PinnedHTTPSConnection(target.host, address)
    tls = check("tls", "TLS sertifikası", "unknown", "HTTPS kontrolü tamamlanamadı.")
    try:
        connection.connect()
        tls = check(
            "tls",
            "TLS sertifikası",
            "clear",
            "Sertifika zinciri ve alan adı doğrulandı. Bu, sitenin güvenilir olduğunu kanıtlamaz.",
        )
        # Headers only: no page body is fetched and redirects are not followed.
        connection.request(
            "HEAD",
            "/",
            headers={"User-Agent": "T3-Phishing-Detection", "Connection": "close"},
        )
        response = connection.getresponse()
        hsts = response.getheader("Strict-Transport-Security", "")
        enabled = bool(
            re.search(
                r"(?:^|;)\s*max-age\s*=\s*\"?[1-9][0-9]*\"?\s*(?:;|$)", hsts, re.I
            )
        )
        return [
            tls,
            check(
                "hsts",
                "HSTS",
                "clear" if enabled else "info",
                (
                    "HTTPS zorunluluğu başlığı bulundu."
                    if enabled
                    else "Pozitif max-age içeren HSTS başlığı görülmedi. Tek başına phishing göstergesi değildir."
                ),
            ),
        ]
    except ssl.SSLCertVerificationError:
        return [
            check("tls", "TLS sertifikası", "warning", "Sertifika doğrulanamadı.", 15),
            check(
                "hsts",
                "HSTS",
                "unknown",
                "TLS doğrulanamadığından kontrol tamamlanamadı.",
            ),
        ]
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return [tls, check("hsts", "HSTS", "unknown", "Sunucudan başlık alınamadı.")]
    finally:
        connection.close()


def inspect_safe_browsing(target, api_key):
    if not api_key or api_key.startswith("YOUR_"):
        return check(
            "safe_browsing",
            "Google Safe Browsing",
            "disabled",
            "API anahtarı yapılandırılmadı; tehdit listesi sorgulanmadı.",
        )
    try:
        response = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": api_key},
            json={
                "client": {"clientId": "t3-phishing-detection", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": target.url}],
                },
            },
            timeout=(TIMEOUT, TIMEOUT),
            allow_redirects=False,
        )
        with response:
            if response.status_code != 200:
                raise ValueError("Provider rejected request")
            data = response.json()
        if not isinstance(data, dict) or "error" in data:
            raise ValueError("Invalid provider response")
        matches = data.get("matches", [])
        if not isinstance(matches, list) or any(
            not isinstance(item, dict) for item in matches
        ):
            raise ValueError("Invalid matches")
        if matches:
            return check(
                "safe_browsing",
                "Google Safe Browsing",
                "danger",
                "Bağlantı bir tehdit listesiyle eşleşti.",
                80,
            )
        return check(
            "safe_browsing",
            "Google Safe Browsing",
            "clear",
            "Sorgulanan listelerde eşleşme bulunmadı. Bu sonuç güvenlik garantisi değildir.",
        )
    except (requests.RequestException, ValueError):
        return check(
            "safe_browsing",
            "Google Safe Browsing",
            "unknown",
            "Servis kontrolü tamamlanamadı; bağlantı hakkında temiz sonucu verilemez.",
        )


def analyze_url(value, api_key=""):
    started = time.perf_counter()
    target = parse_target(value)
    address = resolve_public(target.host)
    parts = urlsplit(target.url)
    depth = len([piece for piece in parts.path.split("/") if piece])
    checks = [
        check(
            "scheme",
            "Bağlantı protokolü",
            "clear" if parts.scheme == "https" else "warning",
            (
                "URL HTTPS kullanıyor."
                if parts.scheme == "https"
                else "URL HTTP kullanıyor; bu bağlantıda taşıma şifrelemesi yok."
            ),
            0 if parts.scheme == "https" else 10,
        ),
        check(
            "length",
            "URL uzunluğu",
            "warning" if len(target.url) > 150 else "clear",
            f"{len(target.url)} karakter. Uzunluk tek başına bir tehdit kanıtı değildir.",
            5 if len(target.url) > 150 else 0,
        ),
        check(
            "depth",
            "Yol derinliği",
            "warning" if depth > 5 else "clear",
            f"{depth} yol bölümü bulundu.",
            5 if depth > 5 else 0,
        ),
        check(
            "ip",
            "Alan adı",
            "warning" if target.is_ip else "clear",
            (
                "Alan adı yerine IP adresi kullanılıyor."
                if target.is_ip
                else "Bir alan adı kullanılıyor."
            ),
            10 if target.is_ip else 0,
        ),
        check(
            "idn",
            "Uluslararası alan adı",
            "info" if "xn--" in target.host else "clear",
            (
                "Punycode alan adı var; yazımı dikkatle karşılaştırın. Bu tek başına kötü niyet göstergesi değildir."
                if "xn--" in target.host
                else "Punycode etiketi bulunmadı."
            ),
        ),
    ]
    with ThreadPoolExecutor(max_workers=2) as executor:
        https_future = executor.submit(inspect_https, target, address)
        browsing_future = executor.submit(inspect_safe_browsing, target, api_key)
        checks.extend(https_future.result())
        checks.append(browsing_future.result())
    risk = min(100, sum(item["points"] for item in checks))
    incomplete = any(item["status"] in ("unknown", "disabled") for item in checks)
    level = (
        "high"
        if risk >= 60
        else "medium" if risk >= 20 else "incomplete" if incomplete else "low"
    )
    return dict(
        url=target.url,
        domain=target.host,
        risk_score=risk,
        risk_level=level,
        incomplete=incomplete,
        completed_checks=sum(
            item["status"] not in ("unknown", "disabled") for item in checks
        ),
        total_checks=len(checks),
        checks=checks,
        duration_ms=round((time.perf_counter() - started) * 1000),
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        methodology="Puan, gözlenen kuralların toplamıdır; phishing olasılığı veya güvenlik garantisi değildir. İçerik ve yönlendirme zinciri analiz edilmez.",
    )
