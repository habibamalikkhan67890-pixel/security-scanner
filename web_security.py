"""web_security.py - API ki apni security: rate limiter, CSRF token, security headers, body size limit.

Scanner sirf doosron ko check nahi karta, khud bhi secure hona chahiye (CSRF, rate limit,
Host header validation, request size limit).
"""
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict
from urllib.parse import urlsplit

from starlette.requests import Request

CSRF_SESSION_KEY = "_csrf_token"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class RateLimiter:
    """Simple in-memory sliding-window limiter (single process ke liye kaafi hai)."""

    def __init__(self, limit: int, window: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self.limit = limit
        self.window = window
        self._clock = clock
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 5000:   # memory growth rokna
                for stale in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
                    self._hits.pop(stale, None)
            return True


def get_csrf_token(request: Request) -> str:
    """Session mein token na ho to naya banata hai (session cookie signed hoti hai)."""
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def csrf_is_valid(request: Request, submitted: str) -> bool:
    expected = request.session.get(CSRF_SESSION_KEY, "")
    return bool(expected) and bool(submitted) and hmac.compare_digest(str(expected), str(submitted))


def client_ip(request: Request) -> str:
    """Direct peer ka IP. X-Forwarded-For jaan boojh kar ignore hota hai (spoof ho sakta hai).
    Next.js proxy ke peeche saare browsers 127.0.0.1 dikhte hain, yani rate limit shared hota hai."""
    return request.client.host if request.client else "unknown"


def host_allowed(host_header: str, allowed_hosts) -> bool:
    try:
        hostname = urlsplit("//" + (host_header or "")).hostname or ""
    except ValueError:
        return False
    return hostname.lower().strip("[]") in allowed_hosts


# API sirf JSON/CSV deti hai, isliye browser ko kuch load karne ki ijazat nahi.
CSP_API = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
# /api/docs (Swagger UI) ko CDN se script/style chahiye - sirf isi path par relaxed CSP.
CSP_DOCS = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
            "worker-src 'self' blob:; frame-ancestors 'none'")


def apply_security_headers(response, is_secure: bool, is_docs: bool = False):
    response.headers.setdefault("Content-Security-Policy", CSP_DOCS if is_docs else CSP_API)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    response.headers["Cache-Control"] = "no-store"
    return response
