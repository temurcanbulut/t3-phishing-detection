import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit, urlunsplit

import idna
import tldextract

SUFFIXES = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


class InvalidTarget(ValueError):
    pass


def is_public(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in ipaddress.IPv6Network("64:ff9b::/96") or ip in ipaddress.IPv6Network(
            "64:ff9b:1::/48"
        ):
            return False
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour or ip.teredo:
            return False
    return ip.is_global and not ip.is_multicast and not ip.is_unspecified


@dataclass(frozen=True)
class Target:
    url: str
    host: str
    scheme: str
    port: int
    is_ip: bool
    display_host: str
    registrable_domain: str


def parse_target(value):
    if not isinstance(value, str) or not value.strip():
        raise InvalidTarget("Bir HTTP/HTTPS bağlantısı veya alan adı girin.")
    value = value.strip()
    if len(value) > 2048 or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise InvalidTarget(
            "URL en fazla 2048 karakter olabilir ve boşluk/kontrol karakteri içeremez."
        )
    if "\\" in value or re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise InvalidTarget("Belirsiz ters eğik çizgi veya bozuk yüzde kodlaması.")
    try:
        parts = urlsplit(value if "://" in value else "https://" + value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError
        if parts.username is not None or parts.password is not None:
            raise InvalidTarget(
                "Kullanıcı bilgisi içeren URL'ler kabul edilmez; gerçek alan adını ayrı inceleyin."
            )
        port = 443 if parts.scheme == "https" else 80
        if parts.port not in (None, port):
            raise InvalidTarget("Yalnızca standart HTTP/HTTPS portları destekleniyor.")
        if parts.hostname.endswith(".."):
            raise ValueError
        raw_host = parts.hostname.rstrip(".")
        if "%" in raw_host:
            raise ValueError
        try:
            ip = ipaddress.ip_address(raw_host)
        except ValueError:
            host = idna.encode(raw_host, uts46=True, std3_rules=True).decode("ascii").lower()
            if (
                len(host) > 253
                or "." not in host
                or all(part.isdigit() for part in host.split("."))
            ):
                raise ValueError from None
            is_ip = False
            display = idna.decode(host)
            suffix = SUFFIXES(host)
            registered = suffix.top_domain_under_public_suffix
        else:
            host = str(ip)
            if not is_public(host):
                raise InvalidTarget("Yerel, özel, geçiş veya ayrılmış ağ adresleri kabul edilmez.")
            is_ip, display, registered = True, host, ""
        authority = f"[{host}]" if ":" in host else host
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="/%?:@!$&'()*+,;=-._~")
        url = urlunsplit((parts.scheme, authority, path, query, ""))
        if len(url) > 4096:
            raise ValueError
        return Target(url, host, parts.scheme, port, is_ip, display, registered)
    except InvalidTarget:
        raise
    except (ValueError, UnicodeError, idna.IDNAError):
        raise InvalidTarget(
            "Geçerli ve belirsizlik içermeyen bir HTTP/HTTPS URL'si girin."
        ) from None
