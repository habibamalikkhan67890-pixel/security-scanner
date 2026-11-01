"""tls_checks.py - TLS handshake inspection (sirf handshake, koi data exploit nahi hota).

Yeh module batata hai: certificate valid hai ya nahi, TLS version/cipher, expiry,
aur kya server purane TLS 1.0/1.1 accept karta hai. Sab connections SSRF guard se guzarte hain.
"""
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import List, Optional

import certifi

from http_client import guarded_connect
from security import TargetPolicy


@dataclass
class TlsReport:
    host: str
    port: int
    reachable: bool = False
    connect_error: Optional[str] = None
    verified: bool = False
    verify_error: Optional[str] = None
    version: Optional[str] = None
    cipher: Optional[str] = None
    not_after: Optional[str] = None
    days_left: Optional[int] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    legacy_accepted: List[str] = field(default_factory=list)
    legacy_note: Optional[str] = None   # legacy probe kyun nahi chala (local OpenSSL support wagera)


def _name_to_text(name_tuple) -> str:
    parts = []
    for rdn in name_tuple or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _handshake(host: str, port: int, policy: TargetPolicy, timeout: float, context: ssl.SSLContext):
    raw = guarded_connect(host, port, policy, timeout)
    try:
        raw.settimeout(timeout)
        return context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise


def inspect_tls(host: str, port: int, policy: TargetPolicy, timeout: float = 8.0) -> TlsReport:
    report = TlsReport(host=host, port=port)

    # 1) verified handshake (certifi CA bundle ke saath)
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        tls = _handshake(host, port, policy, timeout, ctx)
        report.reachable = True
        report.verified = True
        with tls:
            report.version = tls.version()
            cipher = tls.cipher()
            report.cipher = cipher[0] if cipher else None
            cert = tls.getpeercert() or {}
            report.issuer = _name_to_text(cert.get("issuer"))
            report.subject = _name_to_text(cert.get("subject"))
            if cert.get("notAfter"):
                report.not_after = cert["notAfter"]
                report.days_left = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
    except ssl.SSLCertVerificationError as exc:
        report.reachable = True
        report.verify_error = (exc.verify_message or str(exc))[:200]
    except ssl.SSLError as exc:
        report.reachable = True
        report.verify_error = f"TLS handshake failed: {exc.reason or exc}"[:200]
    except (socket.timeout, TimeoutError):
        report.connect_error = "connection timed out"
        return report
    except OSError as exc:
        report.connect_error = str(exc)[:200]
        return report

    # 2) agar verify fail hua to unverified handshake se version/cipher nikaal lo (sirf reporting)
    if not report.verified:
        try:
            loose = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            loose.check_hostname = False
            loose.verify_mode = ssl.CERT_NONE
            with _handshake(host, port, policy, timeout, loose) as tls:
                report.version = tls.version()
                cipher = tls.cipher()
                report.cipher = cipher[0] if cipher else None
        except (ssl.SSLError, OSError):
            pass

    # 3) legacy TLS 1.0/1.1 probe
    report.legacy_accepted, report.legacy_note = _probe_legacy(host, port, policy, timeout)
    return report


def _probe_legacy(host: str, port: int, policy: TargetPolicy, timeout: float):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except (ValueError, ssl.SSLError, AttributeError) as exc:
        return [], f"local OpenSSL cannot offer TLS 1.0/1.1 ({exc})"

    try:
        with _handshake(host, port, policy, timeout, ctx) as tls:
            return [tls.version() or "TLS 1.0/1.1"], None
    except ssl.SSLError as exc:
        reason = str(exc.reason or exc).lower()
        # Server ne protocol version / handshake alert se mana kiya = legacy supported nahi
        if any(word in reason for word in ("protocol version", "alert", "handshake failure", "wrong version",
                                             "unsupported protocol", "no protocols available")):
            if "no protocols available" in reason or "unsupported protocol" in reason:
                return [], "local OpenSSL refused to offer TLS 1.0/1.1, so this probe could not run"
            return [], None
        return [], f"legacy TLS probe inconclusive ({reason[:80]})"
    except OSError as exc:
        return [], f"legacy TLS probe could not connect ({str(exc)[:80]})"
