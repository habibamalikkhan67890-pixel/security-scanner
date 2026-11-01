"""security.py - scanner ko khud secure rakhne wali SSRF protection.

Yeh module teen kaam karta hai:
  1. URL ko validate + normalize karta hai (sirf http/https, no credentials, safe host).
  2. Hostname ko DNS se resolve karke har IP check karta hai (private/loopback/link-local/metadata block).
  3. Wahi check connect ke waqt dobara hota hai (http_client.py) taake DNS rebinding na chale.
"""
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048

# Cloud metadata endpoints - lab mode mein bhi hamesha block rehte hain
METADATA_IPS = {
    ipaddress.ip_address(x)
    for x in (
        "169.254.169.254",   # AWS / GCP / Azure / OpenStack
        "169.254.170.2",     # AWS ECS task metadata
        "100.100.100.200",   # Alibaba Cloud
        "168.63.129.16",     # Azure wireserver
        "192.0.0.192",       # Oracle Cloud
        "fd00:ec2::254",     # AWS IPv6 metadata
    )
}
METADATA_HOSTNAMES = {
    "metadata", "metadata.google.internal", "instance-data", "instance-data.ec2.internal",
    "metadata.azure.internal", "metadata.tencentyun.com",
}
# Lab mode mein sirf yeh private ranges allow hoti hain (loopback alag se)
LAB_PRIVATE_NETWORKS = [
    ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
]

_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$", re.IGNORECASE)
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidURLError(ValueError):
    """URL ka format ghalat hai."""


class UnsafeTargetError(ValueError):
    """Target SSRF policy ke against hai (private/loopback/metadata wagera)."""


class ResolutionError(ValueError):
    """DNS resolve nahi hua."""


Resolver = Callable[..., list]


@dataclass(frozen=True)
class TargetPolicy:
    allow_lab: bool = False
    allowed_ports: Tuple[int, ...] = (80, 443, 8080, 8443)
    resolver: Resolver = field(default=socket.getaddrinfo, compare=False, repr=False)


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int
    ips: Tuple[str, ...]


def _embedded_ipv4(ip) -> List[ipaddress.IPv4Address]:
    """IPv6 ke andar chhupe IPv4 addresses (mapped, 6to4, Teredo, NAT64) nikalta hai."""
    found: List[ipaddress.IPv4Address] = []
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            found.append(ip.ipv4_mapped)
        if ip.sixtofour:
            found.append(ip.sixtofour)
        if ip.teredo:
            found.extend(ip.teredo)
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


def blocked_reason(ip_text: str, policy: TargetPolicy) -> Optional[str]:
    """None matlab IP allowed hai, warna block karne ki wajah string mein."""
    try:
        base = ipaddress.ip_address(ip_text)
    except ValueError:
        return "not a valid IP address"
    for ip in [base] + _embedded_ipv4(base):
        if ip in METADATA_IPS:
            return "cloud metadata endpoint"
        if ip.is_unspecified:
            return "unspecified address"
        if ip.is_multicast:
            return "multicast address"
        if ip.is_link_local:
            return "link-local address"
        if ip.is_loopback:   # reserved se pehle check: IPv6 ::1 Python mein "reserved" bhi hai
            if policy.allow_lab:
                continue
            return "loopback address"
        if ip.is_reserved:
            return "reserved address"
        if ip.is_global:
            continue
        if policy.allow_lab and any(ip in net for net in LAB_PRIVATE_NETWORKS):
            continue
        return "private or non-public address"
    return None


def resolve_and_check(host: str, port: int, policy: TargetPolicy) -> List[str]:
    """Host ko resolve karta hai; agar KOI bhi IP blocked ho to poora target reject."""
    clean = host.strip("[]")
    try:
        ipaddress.ip_address(clean)
        candidates = [clean]
    except ValueError:
        try:
            infos = policy.resolver(clean, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError) as exc:
            raise ResolutionError(f"DNS resolution failed for {clean}: {exc}") from exc
        candidates = []
        for info in infos:
            addr = info[4][0]
            addr = addr.split("%")[0]  # IPv6 scope id hata do
            if addr not in candidates:
                candidates.append(addr)
        if not candidates:
            raise ResolutionError(f"DNS returned no addresses for {clean}")

    for addr in candidates:
        reason = blocked_reason(addr, policy)
        if reason:
            raise UnsafeTargetError(f"{clean} resolves to {addr} ({reason}); target blocked by SSRF protection")
    return candidates


def normalize_url(raw: str) -> str:
    """User input ko saaf, canonical http(s) URL mein badalta hai (network call nahi karta)."""
    if raw is None:
        raise InvalidURLError("URL is required.")
    text = str(raw).strip()
    if not text:
        raise InvalidURLError("URL is required.")
    if len(text) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is too long (max {MAX_URL_LENGTH} characters).")
    if re.search(r"[\s\x00-\x1f\x7f\\]", text):
        raise InvalidURLError("URL contains whitespace, control characters or backslashes.")

    if "://" not in text:
        text = "https://" + text  # scheme na ho to https assume karte hain

    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise InvalidURLError(f"URL could not be parsed: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidURLError("Only http:// and https:// URLs are allowed.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise InvalidURLError("URLs containing credentials (user:pass@host) are not allowed.")

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise InvalidURLError("URL has no host name.")

    is_ip = False
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
        host_text = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    except ValueError:
        host_text = None

    if not is_ip:
        if _NUMERIC_HOST.match(host):
            raise InvalidURLError("Ambiguous numeric IP notation (decimal/hex/octal) is not allowed.")
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise InvalidURLError("Host name is not valid.") from exc
        if len(host) > 253 or not all(_LABEL.match(label) for label in host.split(".")):
            raise InvalidURLError("Host name is not valid.")
        if host in METADATA_HOSTNAMES or host == "localhost" or host.endswith(".localhost"):
            raise UnsafeTargetError(f"Host '{host}' is blocked by SSRF protection.")
        host_text = host

    default_port = 443 if scheme == "https" else 80
    netloc = host_text if port in (None, default_port) else f"{host_text}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))  # fragment hata diya


def validate_url(raw: str, policy: TargetPolicy) -> ValidatedTarget:
    """Poori validation: format + port policy + DNS resolution + IP checks."""
    url = normalize_url(raw)
    parts = urlsplit(url)
    scheme = parts.scheme
    port = parts.port or (443 if scheme == "https" else 80)
    host = parts.hostname or ""

    if not policy.allow_lab and port not in policy.allowed_ports:
        allowed = ", ".join(str(p) for p in policy.allowed_ports)
        raise UnsafeTargetError(f"Port {port} is not allowed (allowed ports: {allowed}).")

    ips = resolve_and_check(host, port, policy)
    return ValidatedTarget(url=url, scheme=scheme, host=host, port=port, ips=tuple(ips))


def pick_safe_ip(host: str, port: int, policy: TargetPolicy) -> str:
    """Connect ke waqt use hota hai: resolve karo, check karo, pehla safe IP wapas do."""
    return resolve_and_check(host, port, policy)[0]


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def same_host(url_a: str, url_b: str) -> bool:
    return (urlsplit(url_a).hostname or "").lower() == (urlsplit(url_b).hostname or "").lower()
