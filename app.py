"""app.py - FastAPI backend (sirf JSON API). Next.js frontend isi se /api/* ke zariye baat karta hai.

Run:  python app.py
 ya:  uvicorn app:create_app --factory --host 127.0.0.1 --port 5000
Docs: http://127.0.0.1:5000/api/docs  (interactive Swagger UI)
"""
import csv
import io
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from config import Settings
from database import Database, DatabaseError
from models import OWASP, SEVERITIES
from scan_service import ScanService, ServiceBusy
from security import InvalidURLError, ResolutionError, UnsafeTargetError, validate_url
from web_security import (
    UNSAFE_METHODS, RateLimiter, apply_security_headers, client_ip, csrf_is_valid, get_csrf_token, host_allowed,
)

logger = logging.getLogger(__name__)

SCAN_MODES = {
    "basic": "Basic checks only (Python)",
    "zap_passive": "Basic checks + OWASP ZAP passive scan",
    "zap_active": "Basic checks + OWASP ZAP ACTIVE scan",
}
NOISE_CHECKS = {"scan-scope", "not-implemented"}   # compare mein shamil nahi
MAX_BODY_BYTES = 16 * 1024                          # API ki requests chhoti hi hoti hain
MAX_ID = 2_147_483_647                              # SQLite integer overflow se bachav

ScanId = Annotated[int, Path(ge=1, le=MAX_ID, description="Scan ki id")]
DEFAULT_ERRORS = {404: "The page or scan you asked for was not found.", 405: "This method is not allowed here."}


# ----------------------------------------------------------------- helpers
def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S") if value else None
    except ValueError:
        return None


def scan_duration(scan: Dict) -> Optional[int]:
    start, end = _parse_dt(scan.get("started_at")), _parse_dt(scan.get("finished_at"))
    return int((end - start).total_seconds()) if start and end else None


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "on", "yes")


def csv_safe(value) -> str:
    """CSV/Excel formula injection se bachav: =,+,-,@ se shuru hone wale cells ke aage ' laga do."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def compare_findings(first: List[Dict], second: List[Dict]) -> Dict[str, List[Dict]]:
    """Do scans ke findings compare karta hai (key = check_id + url + title)."""
    def index(items):
        return {(f["check_id"], f["url"], f["title"]): f for f in items
                if f["check_id"] not in NOISE_CHECKS and f["status"] != "not_completed"}
    a, b = index(first), index(second)
    return {
        "new": [b[k] for k in b if k not in a],
        "resolved": [a[k] for k in a if k not in b],
        "unchanged": [b[k] for k in b if k in a],
    }


def error_response(status: int, message: str) -> JSONResponse:
    return JSONResponse({"ok": False, "error": message}, status_code=status)


class ScanRequest(BaseModel):
    """POST /api/scan ka body. authorized/active_authorized bool ya "on"/"true" string dono chalte hain."""
    url: Optional[str] = Field("", max_length=2048)
    mode: Optional[str] = "basic"
    authorized: Any = False
    active_authorized: Any = False


# ----------------------------------------------------------------- app factory
def create_app(settings: Optional[Settings] = None, service: Optional[ScanService] = None,
               db: Optional[Database] = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if settings.secret_key_generated:
        logger.warning("SECRET_KEY is not set; a random key was generated (sessions reset on restart).")

    db = db or Database(settings.db_path)
    db.init_db()
    db.mark_interrupted()
    service = service or ScanService(settings, db)
    limiter = RateLimiter(settings.rate_limit_per_minute)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        service.shutdown()

    docs = settings.enable_docs
    app = FastAPI(
        title="Security Scanner API", version="2.0", lifespan=lifespan,
        docs_url="/api/docs" if docs else None, redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
    )
    app.state.db, app.state.service, app.state.settings = db, service, settings

    # ------------------------------------------------------------- middleware
    # Order: jo pehle add hota hai woh andar rehta hai. Session andar, security/host guard sab se bahar.
    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="scanner_session",
                       same_site="lax", https_only=settings.cookie_secure, max_age=24 * 3600)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        is_docs = docs and request.url.path.startswith(("/api/docs", "/api/openapi"))
        try:
            if not host_allowed(request.headers.get("host", ""), settings.allowed_hosts):
                response = error_response(400, "Invalid Host header. Add this host to ALLOWED_HOSTS if it is intentional.")
            elif request.method in UNSAFE_METHODS and "transfer-encoding" in request.headers:
                response = error_response(411, "Content-Length is required.")
            elif int(request.headers.get("content-length", "0") or 0) > MAX_BODY_BYTES:
                response = error_response(413, "Request is too large.")
            else:
                response = await call_next(request)
        except ValueError:   # content-length number nahi tha
            response = error_response(400, "Invalid Content-Length header.")
        except Exception:    # last line of defence: traceback client ko nahi dikhate
            logger.exception("Unhandled error on %s %s", request.method, request.url.path)
            response = error_response(500, "Something went wrong on the server.")
        return apply_security_headers(response, request.url.scheme == "https", is_docs)

    # ------------------------------------------------------------- error handlers (hamesha {"ok": false, "error": ...})
    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException):
        default = DEFAULT_ERRORS.get(exc.status_code)
        generic = exc.detail in ("Not Found", "Method Not Allowed")
        return error_response(exc.status_code, default if (default and generic) else str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        errors = exc.errors()
        if errors and errors[0].get("loc", ("",))[0] == "path":
            return error_response(404, DEFAULT_ERRORS[404])
        field = ".".join(str(p) for p in errors[0].get("loc", ())[1:]) if errors else ""
        reason = errors[0].get("msg", "invalid value") if errors else "invalid request"
        return error_response(400, f"Invalid request{': ' + field if field else ''} - {reason}.")

    @app.exception_handler(DatabaseError)
    async def database_error(_request: Request, exc: DatabaseError):
        logger.error("Database error: %s", exc)
        return error_response(500, "A database error occurred. Please try again.")

    # ------------------------------------------------------------- CSRF (har POST par, router level)
    def csrf_guard(request: Request, x_csrf_token: Optional[str] = Header(None)) -> None:
        if request.method in UNSAFE_METHODS and not csrf_is_valid(request, x_csrf_token or ""):
            raise HTTPException(403, "Security token missing or invalid. Reload the page and try again.")

    api = APIRouter(prefix="/api", dependencies=[Depends(csrf_guard)])

    def scan_or_404(scan_id: int, message: str = "Scan not found.") -> Dict:
        scan = db.get_scan(scan_id)
        if scan is None:
            raise HTTPException(404, message)
        return scan

    # ------------------------------------------------------------- read endpoints
    @api.get("/health")
    def health():
        return {"ok": True, "status": "up"}

    @api.get("/csrf")
    def csrf(request: Request):
        """Frontend pehle yeh token leta hai aur phir har POST ke saath X-CSRF-Token header bhejta hai."""
        return {"ok": True, "token": get_csrf_token(request)}

    @api.get("/config")
    def config():
        return {
            "ok": True,
            "lab_mode": settings.allow_lab_targets,
            "active_enabled": settings.zap_active_enabled,
            "scan_modes": SCAN_MODES,
            "severities": list(SEVERITIES),
            "owasp": OWASP,
            "limits": {
                "scan_timeout": int(settings.scan_timeout),
                "max_requests_per_scan": settings.max_requests_per_scan,
                "request_delay": settings.request_delay,
                "max_concurrent_scans": settings.max_concurrent_scans,
                "max_queued_scans": settings.max_queued_scans,
                "rate_limit_per_minute": settings.rate_limit_per_minute,
                "allowed_ports": list(settings.allowed_ports),
            },
        }

    @api.get("/dashboard")
    def dashboard():
        return {"ok": True, **db.dashboard_stats()}

    @api.get("/scans")
    def list_scans(limit: int = Query(300, ge=1, le=1000)):
        return {"ok": True, "scans": db.list_scans(limit=limit)}

    @api.get("/scan/{scan_id}")
    def get_scan(scan_id: ScanId, findings: Optional[str] = None):
        scan = scan_or_404(scan_id)
        payload: Dict[str, Any] = {"ok": True, "scan": scan, "duration_seconds": scan_duration(scan)}
        if scan["status"] in ("completed", "failed", "timeout") or findings == "1":
            payload["findings"] = db.get_findings(scan_id)
        return payload

    @api.get("/compare")
    def compare(a: Optional[int] = Query(None, ge=1, le=MAX_ID), b: Optional[int] = Query(None, ge=1, le=MAX_ID)):
        if not a or not b:
            raise HTTPException(400, "Both scan ids (a and b) are required.")
        scan_a, scan_b = db.get_scan(a), db.get_scan(b)
        if scan_a is None or scan_b is None:
            raise HTTPException(404, "One of the scans was not found.")
        return {
            "ok": True, "scan_a": scan_a, "scan_b": scan_b,
            "same_host": scan_a["host"] == scan_b["host"],
            "result": compare_findings(db.get_findings(a), db.get_findings(b)),
        }

    @api.get("/zap/status")
    def zap_status():
        return {"ok": True, **service.zap_status(), "active_enabled": settings.zap_active_enabled}

    # ------------------------------------------------------------- scan lifecycle
    @api.post("/scan", status_code=201)
    def start_scan(request: Request, body: ScanRequest):
        if not limiter.allow(client_ip(request)):
            raise HTTPException(429, "Too many scan requests. Please wait a minute and try again.")
        if not _truthy(body.authorized):
            raise HTTPException(400, "You must confirm that you own this website or have permission to test it.")
        mode = body.mode or "basic"
        if mode not in SCAN_MODES:
            raise HTTPException(400, "Unknown scan mode.")
        active = mode == "zap_active"
        if active:
            if not settings.zap_active_enabled:
                raise HTTPException(400, "Active scanning is disabled on this server (ZAP_ACTIVE_ENABLED=false).")
            if not _truthy(body.active_authorized):
                raise HTTPException(400, "Active scanning needs a separate explicit confirmation that you are "
                                         "authorized to run intrusive tests against this target.")
        try:
            target = validate_url(body.url or "", service.policy)
        except (InvalidURLError, UnsafeTargetError, ResolutionError) as exc:
            raise HTTPException(400, str(exc))

        scan_id = db.create_scan(target.url, target.host, mode, mode.startswith("zap"), active, True)
        try:
            service.submit(scan_id)
        except ServiceBusy as exc:
            db.delete_scan(scan_id)
            raise HTTPException(503, str(exc))
        return {"ok": True, "scan_id": scan_id, "redirect": f"/report/{scan_id}"}

    @api.post("/scan/{scan_id}/delete")
    def delete_scan(scan_id: ScanId):
        scan = scan_or_404(scan_id)
        if scan["status"] in ("queued", "running"):
            raise HTTPException(409, "This scan is still running and cannot be deleted yet.")
        db.delete_scan(scan_id)
        return {"ok": True}

    @api.post("/history/delete-all")
    def delete_all():
        if any(s["status"] in ("queued", "running") for s in db.list_scans(limit=1000)):
            raise HTTPException(409, "Scans are still running. Wait for them to finish before deleting everything.")
        db.delete_all_scans()
        return {"ok": True}

    # ------------------------------------------------------------- exports
    @api.get("/scan/{scan_id}/export.{fmt}")
    def export_report(scan_id: ScanId, fmt: str):
        if fmt not in ("json", "csv"):
            raise HTTPException(404, "Unknown export format. Use json or csv.")
        scan = scan_or_404(scan_id)
        findings = db.get_findings(scan_id)

        if fmt == "json":
            content = json.dumps({
                "scan": scan,
                "findings": findings,
                "note": "Limited automated scan. Missing findings do not prove a site is secure. "
                        "Status values: confirmed, potential, not_completed.",
            }, indent=2, ensure_ascii=False)
            media_type = "application/json; charset=utf-8"
        else:
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["scan_id", "target", "timestamp", "severity", "status", "title", "affected_url",
                             "owasp", "description", "evidence", "remediation", "source"])
            for f in findings:
                writer.writerow([scan_id, csv_safe(scan["target_url"]), f["created_at"], f["severity"], f["status"],
                                 csv_safe(f["title"]), csv_safe(f["url"]), csv_safe(f["owasp"]),
                                 csv_safe(f["description"]), csv_safe(f["evidence"]),
                                 csv_safe(f["remediation"]), f["source"]])
            content = "﻿" + buffer.getvalue()   # BOM: Excel mein UTF-8 sahi khulti hai
            media_type = "text/csv; charset=utf-8"
        return Response(content, media_type=media_type,
                        headers={"Content-Disposition": f'attachment; filename="security-scan-{scan_id}.{fmt}"'})

    app.include_router(api)
    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings.from_env()
    print(f"Security Scanner API running on http://{settings.host}:{settings.port}/api/  (docs: /api/docs)")
    if settings.allow_lab_targets:
        print("WARNING: ALLOW_LAB_TARGETS=true - loopback/private targets are allowed. Use only for local labs.")
    # proxy_headers=False: X-Forwarded-For par bharosa nahi. Next.js proxy us header ko client se jaisa aaya waisa hi
    # aage bhej deta hai, to koi bhi spoof karke rate limit bypass kar sakta tha. Is liye limit "direct peer" par lagti hai.
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, proxy_headers=False, log_level="info")


if __name__ == "__main__":
    main()
