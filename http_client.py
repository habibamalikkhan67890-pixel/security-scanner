"""http_client.py - scanner ka safe HTTP client.

Safety features:
  * Har redirect hop par URL dobara validate hota hai (scheme, port, DNS, IP).
  * Socket connect ke waqt bhi IP dobara check hota hai (DNS rebinding se bachav).
  * Proxy environment variables ignore hote hain (trust_env=False) taake SSRF guard bypass na ho.
  * Cookies persist nahi hote, body size limited hai, request budget + delay + deadline enforce hoti hai.
"""
import http.cookiejar
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
import urllib3
from urllib3.util import connection as urllib3_connection

from security import (
    TargetPolicy,
    UnsafeTargetError,
    pick_safe_ip,
    validate_url,
)

USER_AGENT = "SecurityScannerEdu/1.0 (authorized security assessment; university project)"


# ----------------------------------------------------------------- exceptions
class FetchError(Exception):
    """Network level failure (timeout, connection refused, too many redirects...)."""


class TlsError(FetchError):
    """Certificate verification ya TLS handshake fail hua."""


class RequestBudgetExceeded(FetchError):
    """Is scan ki request limit poori ho gayi."""


class ScanTimeout(Exception):
    """Poore scan ka time limit khatam."""


# ----------------------------------------------------------------- deadline
class Deadline:
    def __init__(self, seconds: Optional[float]):
        self.expires_at = None if seconds is None else time.monotonic() + seconds

    def remaining(self) -> Optional[float]:
        if self.expires_at is None:
            return None
        return self.expires_at - time.monotonic()

    def expired(self) -> bool:
        remaining = self.remaining()
        return remaining is not None and remaining <= 0

    def check(self) -> None:
        if self.expired():
            raise ScanTimeout("Scan exceeded its time limit.")


# ----------------------------------------------------------------- connection guard
_orig_create_connection = urllib3_connection.create_connection
_guard_state = threading.local()


def _guarded_create_connection(address, *args, **kwargs):
    """urllib3 ka create_connection replace: policy active ho to IP dobara validate karta hai."""
    policy = getattr(_guard_state, "policy", None)
    if policy is None:
        return _orig_create_connection(address, *args, **kwargs)
    host, port = address
    try:
        safe_ip = pick_safe_ip(str(host).strip("[]"), int(port), policy)
    except UnsafeTargetError as exc:
        _guard_state.violation = exc
        raise
    return _orig_create_connection((safe_ip, port), *args, **kwargs)


def install_guard() -> None:
    if urllib3_connection.create_connection is not _guarded_create_connection:
        urllib3_connection.create_connection = _guarded_create_connection


@contextmanager
def guarded(policy: TargetPolicy):
    """With-block ke andar ke saare socket connects SSRF policy se guzarte hain (thread-local)."""
    install_guard()
    previous = getattr(_guard_state, "policy", None)
    _guard_state.policy = policy
    _guard_state.violation = None
    try:
        yield
    finally:
        _guard_state.policy = previous


def guarded_connect(host: str, port: int, policy: TargetPolicy, timeout: float):
    """TLS inspection jaise raw socket kaam ke liye guarded connection."""
    with guarded(policy):
        return urllib3_connection.create_connection((host, port), timeout)


# ----------------------------------------------------------------- result object
@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status: int
    headers: "requests.structures.CaseInsensitiveDict"
    body: bytes
    encoding: str = "utf-8"
    truncated: bool = False
    history: List[Tuple[int, str]] = field(default_factory=list)       # (status, url) redirect chain
    set_cookies: List[Tuple[str, str]] = field(default_factory=list)   # (url, raw Set-Cookie) saare hops ke

    @property
    def text(self) -> str:
        return self.body.decode(self.encoding or "utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "").lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or self.body[:200].lstrip().lower().startswith((b"<!doctype html", b"<html"))


class _BlockAllCookies(http.cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *a, **k: False
    netscape = True
    rfc2965 = hide_cookie2 = False


class SafeHttpClient:
    def __init__(self, settings, deadline: Optional[Deadline] = None, policy: Optional[TargetPolicy] = None):
        self.settings = settings
        self.deadline = deadline or Deadline(None)
        self.policy = policy or TargetPolicy(
            allow_lab=settings.allow_lab_targets, allowed_ports=settings.allowed_ports
        )
        self.requests_made = 0
        self._session = requests.Session()
        self._session.trust_env = False                       # proxy env vars ignore
        self._session.cookies.set_policy(_BlockAllCookies())  # cookies replay nahi hote
        self._session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # -- rate limit / budget
    def _charge(self) -> None:
        self.deadline.check()
        if self.requests_made >= self.settings.max_requests_per_scan:
            raise RequestBudgetExceeded(
                f"Request limit reached ({self.settings.max_requests_per_scan} requests per scan)."
            )
        if self.requests_made > 0 and self.settings.request_delay > 0:
            remaining = self.deadline.remaining()
            delay = self.settings.request_delay if remaining is None else min(self.settings.request_delay, max(0, remaining))
            time.sleep(delay)
            self.deadline.check()
        self.requests_made += 1

    # -- main entry
    def request(self, method: str, url: str, *, headers: Optional[Dict[str, str]] = None,
                max_bytes: Optional[int] = None, follow_redirects: bool = True,
                verify: bool = True) -> FetchResult:
        max_bytes = max_bytes or self.settings.max_body_bytes
        timeout = (self.settings.connect_timeout, self.settings.read_timeout)
        current = url
        history: List[Tuple[int, str]] = []
        cookies: List[Tuple[str, str]] = []

        for _hop in range(self.settings.max_redirects + 1):
            target = validate_url(current, self.policy)   # har hop par poori SSRF validation
            self._charge()
            try:
                with guarded(self.policy):
                    response = self._session.request(
                        method, target.url, headers=headers, timeout=timeout,
                        allow_redirects=False, stream=True, verify=verify,
                    )
            except UnsafeTargetError:
                raise
            except requests.exceptions.SSLError as exc:
                raise TlsError(_short_error(exc)) from exc
            except requests.exceptions.RequestException as exc:
                violation = getattr(_guard_state, "violation", None)
                if violation is not None:
                    _guard_state.violation = None
                    raise violation from exc
                raise FetchError(_short_error(exc)) from exc

            try:
                raw_cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
                cookies.extend((target.url, c) for c in raw_cookies)

                location = response.headers.get("Location")
                if follow_redirects and 300 <= response.status_code < 400 and location:
                    history.append((response.status_code, target.url))
                    current = urljoin(target.url, location)
                    continue

                body, truncated = _read_limited(response, max_bytes, self.deadline)
                return FetchResult(
                    requested_url=url, final_url=target.url, status=response.status_code,
                    headers=response.headers, body=body, encoding=response.encoding or "utf-8",
                    truncated=truncated, history=history, set_cookies=cookies,
                )
            finally:
                response.close()

        raise FetchError(f"Too many redirects (limit {self.settings.max_redirects}).")

    def get(self, url: str, **kwargs) -> FetchResult:
        return self.request("GET", url, **kwargs)

    def close(self) -> None:
        self._session.close()


def _read_limited(response, max_bytes: int, deadline: Deadline) -> Tuple[bytes, bool]:
    chunks, total, truncated = [], 0, False
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                chunks.append(chunk[: max_bytes - (total - len(chunk))])
                truncated = True
                break
            chunks.append(chunk)
            deadline.check()
    except requests.exceptions.RequestException as exc:
        raise FetchError(_short_error(exc)) from exc
    return b"".join(chunks), truncated


def _short_error(exc: Exception) -> str:
    text = str(exc)
    for marker in ("certificate verify failed", "CERTIFICATE_VERIFY_FAILED"):
        if marker in text:
            return "TLS certificate verification failed: " + text.split("(")[-1].strip(") ")[:200]
    if "Max retries exceeded" in text and "Caused by" in text:
        text = text.split("Caused by", 1)[1].strip(" :'\"")
    return text[:300]
