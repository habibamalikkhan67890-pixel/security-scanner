"""config.py - saari settings yahan se aati hain (environment variables ya .env file).

Secrets (SECRET_KEY, ZAP_API_KEY) kabhi code mein hardcode nahi kiye jate.
"""
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Tuple

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent


def _get_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _get_int(env: Mapping[str, str], name: str, default: int,
             minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    raw = env.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _get_float(env: Mapping[str, str], name: str, default: float,
               minimum: float = 0.0, maximum: float = 3600.0) -> float:
    raw = env.get(name)
    try:
        value = float(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _get_ports(env: Mapping[str, str], name: str, default: Tuple[int, ...]) -> Tuple[int, ...]:
    raw = env.get(name)
    if not raw:
        return default
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit() and 0 < int(part) < 65536:
            ports.append(int(part))
    return tuple(ports) or default


@dataclass(frozen=True)
class Settings:
    # --- API server ---
    secret_key: str
    secret_key_generated: bool
    db_path: str
    host: str
    port: int
    cookie_secure: bool              # HTTPS par deploy karein to true (cookie sirf HTTPS par jayegi)
    enable_docs: bool                # /api/docs (Swagger UI)
    # --- SSRF / target policy ---
    allow_lab_targets: bool          # sirf local lab testing ke liye (loopback + private IP allow)
    allowed_ports: Tuple[int, ...]
    allowed_hosts: Tuple[str, ...]   # Host header allow-list (DNS rebinding se app ko bachane ke liye)
    # --- HTTP client limits ---
    connect_timeout: float
    read_timeout: float
    max_body_bytes: int
    max_redirects: int
    request_delay: float             # do requests ke beech wait (rate limit)
    max_requests_per_scan: int
    # --- scan service ---
    scan_timeout: float
    max_concurrent_scans: int
    max_queued_scans: int
    rate_limit_per_minute: int       # /scan endpoint par per-IP limit
    # --- OWASP ZAP ---
    zap_url: str
    zap_api_key: str
    zap_timeout: float               # ZAP API call ka timeout
    zap_spider_max_depth: int
    zap_spider_max_children: int
    zap_spider_max_minutes: int
    zap_active_enabled: bool         # active scan ko admin level par on/off karna
    zap_active_max_minutes: int
    zap_active_delay_ms: int
    zap_threads: int
    zap_new_session_per_scan: bool

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        """env=None ho to os.environ (aur .env file) use hoti hai."""
        if env is None:
            load_dotenv(BASE_DIR / ".env")
            env = os.environ

        secret = env.get("SECRET_KEY", "").strip()
        generated = False
        if not secret or secret.lower().startswith("change-me"):
            # Key nahi di gayi to random bana lete hain (restart par sessions reset ho jayenge)
            secret = secrets.token_hex(32)
            generated = True

        db_path = env.get("DATABASE_PATH", "").strip() or str(BASE_DIR / "instance" / "scanner.db")

        return cls(
            secret_key=secret,
            secret_key_generated=generated,
            db_path=db_path,
            host=env.get("API_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=_get_int(env, "API_PORT", 5000, 1, 65535),
            cookie_secure=_get_bool(env, "COOKIE_SECURE", False),
            enable_docs=_get_bool(env, "ENABLE_DOCS", True),
            allow_lab_targets=_get_bool(env, "ALLOW_LAB_TARGETS", False),
            allowed_ports=_get_ports(env, "ALLOWED_PORTS", (80, 443, 8080, 8443)),
            allowed_hosts=tuple(
                h.strip().lower().strip("[]")
                for h in (env.get("ALLOWED_HOSTS") or "localhost,127.0.0.1,::1").split(",") if h.strip()
            ),
            connect_timeout=_get_float(env, "CONNECT_TIMEOUT", 5.0, 1.0, 60.0),
            read_timeout=_get_float(env, "READ_TIMEOUT", 10.0, 1.0, 120.0),
            max_body_bytes=_get_int(env, "MAX_BODY_BYTES", 524288, 4096, 5_000_000),
            max_redirects=_get_int(env, "MAX_REDIRECTS", 5, 0, 10),
            request_delay=_get_float(env, "REQUEST_DELAY", 0.25, 0.0, 10.0),
            max_requests_per_scan=_get_int(env, "MAX_REQUESTS_PER_SCAN", 80, 5, 500),
            scan_timeout=_get_float(env, "SCAN_TIMEOUT", 180.0, 5.0, 3600.0),
            max_concurrent_scans=_get_int(env, "MAX_CONCURRENT_SCANS", 2, 1, 8),
            max_queued_scans=_get_int(env, "MAX_QUEUED_SCANS", 10, 0, 100),
            rate_limit_per_minute=_get_int(env, "RATE_LIMIT_PER_MINUTE", 6, 1, 600),
            zap_url=env.get("ZAP_URL", "http://127.0.0.1:8090").strip().rstrip("/"),
            zap_api_key=env.get("ZAP_API_KEY", "").strip(),
            zap_timeout=_get_float(env, "ZAP_TIMEOUT", 10.0, 1.0, 120.0),
            zap_spider_max_depth=_get_int(env, "ZAP_SPIDER_MAX_DEPTH", 2, 1, 10),
            zap_spider_max_children=_get_int(env, "ZAP_SPIDER_MAX_CHILDREN", 20, 1, 500),
            zap_spider_max_minutes=_get_int(env, "ZAP_SPIDER_MAX_MINUTES", 2, 1, 30),
            zap_active_enabled=_get_bool(env, "ZAP_ACTIVE_ENABLED", False),
            zap_active_max_minutes=_get_int(env, "ZAP_ACTIVE_MAX_MINUTES", 5, 1, 60),
            zap_active_delay_ms=_get_int(env, "ZAP_ACTIVE_DELAY_MS", 200, 0, 5000),
            zap_threads=_get_int(env, "ZAP_THREADS", 2, 1, 10),
            zap_new_session_per_scan=_get_bool(env, "ZAP_NEW_SESSION_PER_SCAN", False),
        )
