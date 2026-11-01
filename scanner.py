"""scanner.py - built-in Python security checks (Requests + BeautifulSoup).

Yeh scanner NON-INTRUSIVE hai: sirf GET/OPTIONS/TRACE jaisi safe requests, limited paths,
koi exploit, brute force ya payload injection nahi. Har finding ka status honest hota hai:
confirmed / potential / not_completed. Kabhi "site secure hai" ka claim nahi kiya jata.
"""
import logging
import re
import secrets
import ssl
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from http_client import (
    Deadline, FetchError, FetchResult, RequestBudgetExceeded, SafeHttpClient, ScanTimeout, TlsError,
)
from models import OWASP, SEVERITY_RANK, Finding
from security import ResolutionError, UnsafeTargetError, ValidatedTarget, origin_of, validate_url
from tls_checks import TlsReport, inspect_tls

logger = logging.getLogger(__name__)

SESSION_COOKIE_RE = re.compile(r"(sess|sid|auth|token|jwt|login|csrf|xsrf|connect\.sid|asp\.net)", re.I)
CSRF_FIELD_RE = re.compile(r"(csrf|xsrf|token|nonce|authenticity|__requestverificationtoken|_wpnonce)", re.I)
VERSION_RE = re.compile(r"\d+(\.\d+)+")
DIR_LISTING_RE = re.compile(
    r"(<title>\s*Index of /|<h1>\s*Index of /|<title>\s*Directory listing for|>\s*Parent Directory\s*<)", re.I)
ERROR_SIGNATURES = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python traceback"),
    (re.compile(r"(Fatal error|Warning|Notice):.{0,200} on line \d+", re.S), "PHP error message"),
    (re.compile(r"\bat [\w.$]+\([\w$]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"System\.[A-Za-z.]+Exception"), ".NET exception"),
    (re.compile(r"You have an error in your SQL syntax|SQLSTATE\["), "database error message"),
    (re.compile(r"Werkzeug Debugger|The debugger caught an exception"), "Werkzeug debugger page"),
    (re.compile(r"Server Error in '/' Application"), "ASP.NET error page"),
]
TRACKING_NOTE = "content not stored"
RISKY_METHODS = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE"}

REMEDIATION = {
    "csp": "Add a Content-Security-Policy header that restricts script, style and frame sources "
           "(start with default-src 'self'; frame-ancestors 'self') and test it in report-only mode first.",
    "hsts": "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once all subdomains support HTTPS.",
    "xfo": "Send X-Frame-Options: DENY (or SAMEORIGIN) or a CSP frame-ancestors directive.",
    "xcto": "Send X-Content-Type-Options: nosniff on all responses.",
    "referrer": "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    "permissions": "Send a Permissions-Policy header that disables browser features the site does not use.",
    "https": "Serve the whole site over HTTPS with a valid certificate and redirect all HTTP requests to HTTPS.",
    "expose": "Remove the file from the web root or deny access in the web server configuration, "
              "then rotate any credentials or secrets it may have contained.",
}


# ----------------------------------------------------------------- helpers
class TargetUnreachable(Exception):
    """Pehla request hi nahi ho saka - scan aage nahi barh sakta."""

    def __init__(self, message: str, blocked: bool = False):
        super().__init__(message)
        self.blocked = blocked


@dataclass
class ScanOutcome:
    findings: List[Finding]
    requests_made: int
    timed_out: bool = False


@dataclass
class ScanContext:
    target: ValidatedTarget
    client: SafeHttpClient
    home: Optional[FetchResult] = None
    soup: Optional[BeautifulSoup] = None
    final_url: str = ""
    tls_report: Optional[TlsReport] = None
    findings: List[Finding] = field(default_factory=list)

    @property
    def final(self):
        return urlsplit(self.final_url)

    @property
    def is_https(self) -> bool:
        return self.final.scheme == "https"

    def add(self, check_id, title, severity, status, description, evidence, owasp_key, remediation, url=None):
        self.findings.append(Finding(
            check_id=check_id, title=title, severity=severity, status=status, url=url or self.final_url,
            description=description, evidence=evidence,
            owasp=OWASP.get(owasp_key, owasp_key), remediation=remediation,
        ))

    def not_completed(self, check_id, title, reason, url=None):
        self.add(check_id, f"Check not completed: {title}", "Informational", "not_completed",
                 "This check could not be completed, so no conclusion can be drawn about it.",
                 reason, "A02", "Re-run the scan, or verify this item manually.", url)


def _looks_html(data: bytes) -> bool:
    head = data[:512].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or b"<html" in head


def parse_set_cookie(raw: str) -> Tuple[str, Dict[str, str], str]:
    """Raw Set-Cookie se (name, attributes, redacted_text) nikalta hai. Cookie ki value kabhi store nahi hoti."""
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    attrs: Dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    redacted = "; ".join([f"{name}=<redacted>"] + parts[1:])
    return name, attrs, redacted


def parse_csp(value: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for chunk in value.split(";"):
        tokens = chunk.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def _worst(severities: List[str]) -> str:
    return min(severities, key=lambda s: SEVERITY_RANK[s])


# ----------------------------------------------------------------- sensitive file signatures
def _v_git_head(b: bytes) -> bool:
    return not _looks_html(b) and (b.lstrip().startswith(b"ref:") or bool(re.fullmatch(rb"[0-9a-f]{40}\s*", b[:64])))


def _v_git_config(b: bytes) -> bool:
    return not _looks_html(b) and b"[core]" in b[:2048]


def _v_dotenv(b: bytes) -> bool:
    return not _looks_html(b) and bool(re.search(rb"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+", b[:4096], re.M))


def _v_ds_store(b: bytes) -> bool:
    return b[:8] == b"\x00\x00\x00\x01Bud1" or b"Bud1" in b[:16]


def _v_phpinfo(b: bytes) -> bool:
    return b"phpinfo()" in b or b"PHP Version" in b


def _v_server_status(b: bytes) -> bool:
    return b"Apache Server Status" in b or b"Server Version:" in b[:4000]


def _v_sql(b: bytes) -> bool:
    return not _looks_html(b) and bool(re.search(rb"(CREATE TABLE|INSERT INTO|mysqldump|PostgreSQL database dump)", b[:65536], re.I))


def _v_zip(b: bytes) -> bool:
    return b[:4] == b"PK\x03\x04"


def _v_gzip(b: bytes) -> bool:
    return b[:2] == b"\x1f\x8b"


def _v_dbpass(b: bytes) -> bool:
    return not _looks_html(b) and (b"DB_PASSWORD" in b or b"DB_USER" in b or b"password" in b[:65536].lower())


def _v_web_config(b: bytes) -> bool:
    return b"<configuration" in b[:4096].lower()


def _v_htpasswd(b: bytes) -> bool:
    return not _looks_html(b) and bool(re.search(rb"^[\w.-]+:(\$|\{SHA\}|[A-Za-z0-9./]{13})", b[:2048], re.M))


def _v_idea(b: bytes) -> bool:
    return b"<project" in b[:2048]


def _v_phpmyadmin(b: bytes) -> bool:
    return b"phpMyAdmin" in b


# (path, title, severity, validator, signature description)
SENSITIVE_PATHS = [
    ("/.git/HEAD", "Exposed Git repository metadata (/.git/HEAD)", "High", _v_git_head, "a Git HEAD reference"),
    ("/.git/config", "Exposed Git configuration (/.git/config)", "High", _v_git_config, "a Git [core] section"),
    ("/.env", "Exposed environment file (/.env)", "High", _v_dotenv, "KEY=VALUE environment entries"),
    ("/.htpasswd", "Exposed password file (/.htpasswd)", "High", _v_htpasswd, "user:hash entries"),
    ("/backup.sql", "Exposed database dump (/backup.sql)", "High", _v_sql, "SQL dump statements"),
    ("/database.sql", "Exposed database dump (/database.sql)", "High", _v_sql, "SQL dump statements"),
    ("/dump.sql", "Exposed database dump (/dump.sql)", "High", _v_sql, "SQL dump statements"),
    ("/backup.zip", "Exposed backup archive (/backup.zip)", "High", _v_zip, "a ZIP archive header"),
    ("/backup.tar.gz", "Exposed backup archive (/backup.tar.gz)", "High", _v_gzip, "a gzip archive header"),
    ("/wp-config.php.bak", "Exposed configuration backup (/wp-config.php.bak)", "High", _v_dbpass, "database credential keywords"),
    ("/config.php.bak", "Exposed configuration backup (/config.php.bak)", "High", _v_dbpass, "database credential keywords"),
    ("/phpinfo.php", "Exposed phpinfo() page (/phpinfo.php)", "Medium", _v_phpinfo, "phpinfo() output"),
    ("/info.php", "Exposed phpinfo() page (/info.php)", "Medium", _v_phpinfo, "phpinfo() output"),
    ("/server-status", "Exposed Apache server-status (/server-status)", "Medium", _v_server_status, "Apache status page"),
    ("/web.config", "Exposed web.config (/web.config)", "Medium", _v_web_config, "an XML <configuration> root"),
    ("/phpmyadmin/", "phpMyAdmin interface reachable (/phpmyadmin/)", "Medium", _v_phpmyadmin, "the phpMyAdmin banner"),
    ("/.DS_Store", "Exposed macOS metadata file (/.DS_Store)", "Low", _v_ds_store, "a .DS_Store header"),
    ("/.idea/workspace.xml", "Exposed IDE project file (/.idea/workspace.xml)", "Low", _v_idea, "an IDE <project> document"),
]
LISTING_PATHS = ["/uploads/", "/backup/", "/logs/", "/files/"]


# ----------------------------------------------------------------- scanner
class SecurityScanner:
    def __init__(self, settings, deadline: Optional[Deadline] = None,
                 progress: Optional[Callable[[int, str], None]] = None,
                 client: Optional[SafeHttpClient] = None):
        self.settings = settings
        self.deadline = deadline or Deadline(settings.scan_timeout)
        self.progress = progress or (lambda pct, step: None)
        self.client = client or SafeHttpClient(settings, self.deadline)

    # -- public
    def run(self, target_url: str) -> ScanOutcome:
        target = validate_url(target_url, self.client.policy)   # UnsafeTargetError/InvalidURLError propagate
        ctx = ScanContext(target=target, client=self.client)

        self.progress(5, "Fetching target")
        self._fetch_home(ctx)

        steps = [
            ("Checking HTTPS and TLS", 20, self._check_https_tls),
            ("Checking security headers", 35, self._check_security_headers),
            ("Checking CORS configuration", 45, self._check_cors),
            ("Checking cookies", 52, self._check_cookies),
            ("Checking information disclosure", 58, self._check_info_disclosure),
            ("Analysing HTML (forms, mixed content, SRI)", 66, self._check_html),
            ("Checking HTTP methods", 74, self._check_methods),
            ("Probing sensitive files and directory listings", 90, self._check_exposure),
        ]
        timed_out = False
        try:
            for index, (label, pct, func) in enumerate(steps):
                self.progress(pct, label)
                try:
                    func(ctx)
                except ScanTimeout:
                    raise
                except (UnsafeTargetError, ResolutionError, FetchError, OSError, ssl.SSLError) as exc:
                    # RequestBudgetExceeded bhi FetchError hai: step not_completed ho jata hai, scan chalta rehta hai
                    ctx.not_completed(f"step-{index}", label, f"{type(exc).__name__}: {exc}")
                except Exception as exc:  # koi bug poora scan nahi girana chahiye
                    logger.exception("Check failed: %s", label)
                    ctx.not_completed(f"step-{index}", label, f"internal error ({type(exc).__name__})")
        except ScanTimeout:
            timed_out = True
            ctx.not_completed("scan-timeout", "remaining checks",
                              f"The scan time limit ({self.settings.scan_timeout:.0f}s) was reached; "
                              "later checks were skipped and results are partial.")

        self._add_scope_notes(ctx)
        findings = sorted(ctx.findings, key=lambda f: (f.status == "not_completed", SEVERITY_RANK[f.severity]))
        self.progress(100, "Finished")
        return ScanOutcome(findings=findings, requests_made=self.client.requests_made, timed_out=timed_out)

    # -- step 0
    def _fetch_home(self, ctx: ScanContext) -> None:
        url = ctx.target.url
        try:
            try:
                ctx.home = self.client.get(url)
            except TlsError as exc:
                # Certificate galat hai - phir bhi headers analyse karne ke liye unverified retry karte hain
                ctx.home = self.client.get(url, verify=False)
                ctx.add("tls-verify-fetch", "Page fetched without certificate verification", "Informational",
                        "confirmed", "The certificate could not be verified, so the page was fetched without "
                        "verification only to analyse its headers and content.", str(exc), "A04",
                        REMEDIATION["https"], url)
        except (UnsafeTargetError, ResolutionError) as exc:
            raise TargetUnreachable(str(exc), blocked=isinstance(exc, UnsafeTargetError)) from exc
        except FetchError as exc:
            raise TargetUnreachable(f"Could not reach target: {exc}") from exc

        ctx.final_url = ctx.home.final_url
        if ctx.home.is_html:
            ctx.soup = BeautifulSoup(ctx.home.text, "html.parser")   # sirf parse; koi script execute nahi hoti

    # -- 1. HTTPS / TLS
    def _check_https_tls(self, ctx: ScanContext) -> None:
        policy = self.client.policy
        timeout = self.settings.connect_timeout + 3
        final = ctx.final
        host = final.hostname or ""

        if ctx.is_https:
            report = inspect_tls(host, final.port or 443, policy, timeout)
            ctx.tls_report = report
            self._tls_findings(ctx, report)
            if (final.port or 443) == 443:
                self._check_http_redirect(ctx)
            return

        entered_https = ctx.target.scheme == "https"
        if entered_https:
            ctx.add("https-downgrade", "HTTPS request redirects to plain HTTP", "High", "confirmed",
                    "The site redirected an HTTPS request to an unencrypted HTTP URL.",
                    f"{ctx.target.url} -> {ctx.final_url}", "A04", REMEDIATION["https"])
            return

        if (final.port or 80) == 80:
            report = inspect_tls(host, 443, policy, timeout)
            ctx.tls_report = report
            if report.connect_error:
                ctx.add("no-https", "HTTPS is not available", "High", "confirmed",
                        "The site is served only over unencrypted HTTP, so traffic can be read or modified in transit.",
                        f"Served over http://; connecting to {host}:443 failed ({report.connect_error}).",
                        "A04", REMEDIATION["https"])
            else:
                ctx.add("http-no-redirect", "HTTP does not redirect to HTTPS", "Medium", "confirmed",
                        "The site is reachable over plain HTTP without being redirected to HTTPS, "
                        "although HTTPS is also available.",
                        f"{ctx.target.url} returned HTTP {ctx.home.status} without redirecting to HTTPS.",
                        "A04", REMEDIATION["https"])
                self._tls_findings(ctx, report)
        else:
            ctx.add("no-https", "Site is served over unencrypted HTTP", "High", "confirmed",
                    "The page was delivered over plain HTTP, so traffic can be read or modified in transit.",
                    f"Final URL uses http:// on port {final.port}.", "A04", REMEDIATION["https"])
            ctx.not_completed("https-availability", "HTTPS availability",
                              f"Target uses non-standard port {final.port}; HTTPS on port 443 was not assumed or tested.")

    def _tls_findings(self, ctx: ScanContext, report: TlsReport) -> None:
        url = f"https://{report.host}:{report.port}/"
        if report.connect_error:
            ctx.not_completed("tls-handshake", "TLS inspection", report.connect_error, url)
            return
        if report.verify_error:
            low = report.verify_error.lower()
            if "expired" in low:
                title = "TLS certificate has expired"
            elif "hostname" in low or "ip address mismatch" in low:
                title = "TLS certificate does not match the host name"
            elif "self-signed" in low or "self signed" in low or "local issuer" in low:
                title = "TLS certificate is self-signed or from an untrusted issuer"
            else:
                title = "TLS certificate validation failed"
            ctx.add("tls-cert", title, "High", "confirmed",
                    "Browsers will warn users, and clients cannot trust the identity of this server.",
                    report.verify_error, "A04", "Install a valid certificate from a trusted CA that matches the "
                    "host name and renew it before it expires.", url)
        if report.legacy_accepted:
            ctx.add("tls-legacy", "Legacy TLS 1.0/1.1 is accepted", "Medium", "confirmed",
                    "The server completed a handshake using a deprecated TLS version.",
                    f"Handshake succeeded with {', '.join(report.legacy_accepted)}.", "A04",
                    "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and TLS 1.3.", url)
        elif report.legacy_note:
            ctx.not_completed("tls-legacy", "legacy TLS 1.0/1.1 probe", report.legacy_note, url)
        if report.days_left is not None and report.days_left < 30:
            ctx.add("tls-expiry", "TLS certificate expires soon", "Low", "confirmed",
                    "An expired certificate will cause outages and browser warnings.",
                    f"Certificate expires {report.not_after} ({report.days_left} days left).", "A04",
                    "Renew the certificate and automate renewal (for example with ACME/Let's Encrypt).", url)
        summary = [f"negotiated {report.version or 'unknown version'}", f"cipher {report.cipher or 'unknown'}"]
        if report.not_after:
            summary.append(f"certificate valid until {report.not_after} ({report.days_left} days)")
        if report.issuer:
            summary.append(f"issuer {report.issuer}")
        ctx.add("tls-summary", "TLS configuration summary", "Informational", "confirmed",
                "Observed TLS parameters of the server (informational, not a full TLS audit).",
                "; ".join(summary), "A04", "No action required unless other TLS findings are listed.", url)

    def _check_http_redirect(self, ctx: ScanContext) -> None:
        host = ctx.final.netloc
        http_url = urlunsplit(("http", host, "/", "", ""))
        try:
            response = self.client.request("GET", http_url, follow_redirects=False, max_bytes=4096)
        except (ScanTimeout, RequestBudgetExceeded):
            raise
        except (FetchError, UnsafeTargetError, ResolutionError):
            return  # port 80 band hai - HTTPS-only site, theek hai
        if 300 <= response.status < 400:
            location = urljoin(http_url, response.headers.get("Location", ""))
            if not location.lower().startswith("https://"):
                ctx.add("http-redirect", "HTTP redirect does not point to HTTPS", "Low", "confirmed",
                        "Plain HTTP requests are redirected, but not to an HTTPS URL.",
                        f"{http_url} -> {location}", "A04", REMEDIATION["https"], http_url)
        elif response.status < 400:
            ctx.add("http-no-redirect", "Plain HTTP version of the site is served without redirect", "Medium",
                    "confirmed", "Users who type http:// get an unencrypted session instead of being upgraded.",
                    f"GET {http_url} returned HTTP {response.status} without redirecting to HTTPS.",
                    "A04", REMEDIATION["https"], http_url)

    # -- 2. security headers
    def _check_security_headers(self, ctx: ScanContext) -> None:
        h = ctx.home.headers
        csp = h.get("Content-Security-Policy", "").strip()
        report_only = h.get("Content-Security-Policy-Report-Only", "").strip()

        if not csp:
            if report_only:
                ctx.add("hdr-csp", "Content-Security-Policy is report-only", "Low", "confirmed",
                        "CSP is sent in report-only mode, so it does not block anything.",
                        "Only Content-Security-Policy-Report-Only is present.", "A02", REMEDIATION["csp"])
            else:
                ctx.add("hdr-csp", "Missing Content-Security-Policy header", "Medium", "confirmed",
                        "CSP limits where scripts and other content may load from and reduces the impact of XSS.",
                        "Response has no Content-Security-Policy header.", "A02", REMEDIATION["csp"])
        else:
            directives = parse_csp(csp)
            script_src = directives.get("script-src") or directives.get("default-src") or []
            issues = []
            hardened = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
                           for t in script_src)
            if "'unsafe-inline'" in script_src and not hardened:
                issues.append("script policy allows 'unsafe-inline'")
            if "'unsafe-eval'" in script_src:
                issues.append("script policy allows 'unsafe-eval'")
            if any(t in ("*", "data:", "http:") for t in script_src):
                issues.append("script policy allows wildcard/data:/http: sources")
            if issues:
                ctx.add("hdr-csp-weak", "Weak Content-Security-Policy", "Low", "potential",
                        "The CSP contains directives that weaken its protection against XSS.",
                        "; ".join(issues), "A02", REMEDIATION["csp"])

        if ctx.is_https:
            hsts = h.get("Strict-Transport-Security", "").strip()
            if not hsts:
                ctx.add("hdr-hsts", "Missing Strict-Transport-Security (HSTS) header", "Medium", "confirmed",
                        "Without HSTS browsers may connect over HTTP first, enabling downgrade attacks.",
                        "HTTPS response has no Strict-Transport-Security header.", "A02", REMEDIATION["hsts"])
            else:
                match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
                if not match or int(match.group(1)) < 15552000:
                    ctx.add("hdr-hsts-weak", "HSTS max-age is too short", "Low", "confirmed",
                            "A short HSTS lifetime gives limited downgrade protection.",
                            f"Strict-Transport-Security: {hsts[:120]}", "A02", REMEDIATION["hsts"])

        xfo = h.get("X-Frame-Options", "").strip()
        frame_ancestors = bool(csp) and "frame-ancestors" in csp.lower()
        if not xfo and not frame_ancestors:
            ctx.add("hdr-xfo", "Missing clickjacking protection", "Medium", "confirmed",
                    "The page can be embedded in a frame on another site (clickjacking).",
                    "Neither X-Frame-Options nor CSP frame-ancestors is present.", "A02", REMEDIATION["xfo"])
        elif xfo.upper().startswith("ALLOW-FROM"):
            ctx.add("hdr-xfo-weak", "Obsolete X-Frame-Options ALLOW-FROM value", "Low", "confirmed",
                    "ALLOW-FROM is not supported by modern browsers.", f"X-Frame-Options: {xfo[:80]}", "A02",
                    REMEDIATION["xfo"])

        if "nosniff" not in h.get("X-Content-Type-Options", "").lower():
            ctx.add("hdr-xcto", "Missing X-Content-Type-Options: nosniff", "Low", "confirmed",
                    "Browsers may MIME-sniff responses and treat data as executable content.",
                    "X-Content-Type-Options header is absent or not 'nosniff'.", "A02", REMEDIATION["xcto"])

        referrer = h.get("Referrer-Policy", "").strip().lower()
        if not referrer:
            ctx.add("hdr-referrer", "Missing Referrer-Policy header", "Low", "confirmed",
                    "Full URLs (which may contain tokens or IDs) can leak to other sites through the Referer header.",
                    "Referrer-Policy header is absent.", "A02", REMEDIATION["referrer"])
        elif referrer == "unsafe-url":
            ctx.add("hdr-referrer-weak", "Weak Referrer-Policy (unsafe-url)", "Low", "confirmed",
                    "The full URL is sent as referrer to every destination.", "Referrer-Policy: unsafe-url", "A02",
                    REMEDIATION["referrer"])

        if not h.get("Permissions-Policy") and not h.get("Feature-Policy"):
            ctx.add("hdr-permissions", "Missing Permissions-Policy header", "Informational", "confirmed",
                    "Permissions-Policy lets the site disable unused browser features (camera, microphone, ...).",
                    "Permissions-Policy header is absent.", "A02", REMEDIATION["permissions"])

    # -- 2b. CORS
    def _check_cors(self, ctx: ScanContext) -> None:
        h = ctx.home.headers
        acao = h.get("Access-Control-Allow-Origin", "").strip()
        acac = h.get("Access-Control-Allow-Credentials", "").strip().lower()
        if acao == "*" and acac == "true":
            ctx.add("cors-wildcard-creds", "CORS wildcard combined with credentials", "Medium", "potential",
                    "An invalid/dangerous CORS combination; exploitability depends on the data served.",
                    "Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true", "A02",
                    "Return an explicit allow-list of trusted origins and never combine * with credentials.")
        elif acao == "*":
            ctx.add("cors-wildcard", "CORS allows any origin", "Informational", "confirmed",
                    "Any website can read responses from this URL. This is fine for public data only.",
                    "Access-Control-Allow-Origin: *", "A02", "Restrict CORS to trusted origins if the data is not public.")

        probe_origin = "https://scanner-cors-test.invalid"
        response = self.client.request("GET", ctx.final_url, headers={"Origin": probe_origin},
                                       follow_redirects=False, max_bytes=4096)
        reflected = response.headers.get("Access-Control-Allow-Origin", "").strip()
        if reflected == probe_origin:
            creds = response.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
            ctx.add("cors-reflect", "CORS reflects an arbitrary Origin" + (" with credentials" if creds else ""),
                    "Medium" if creds else "Low", "potential",
                    "The server echoed back an untrusted Origin header. Impact depends on whether sensitive "
                    "data is returned for authenticated users.",
                    f"Origin: {probe_origin} -> Access-Control-Allow-Origin: {reflected}"
                    + ("; Access-Control-Allow-Credentials: true" if creds else ""),
                    "A02", "Validate Origin against a fixed allow-list instead of reflecting it.")

    # -- 3. cookies
    def _check_cookies(self, ctx: ScanContext) -> None:
        seen = set()
        for set_url, raw in ctx.home.set_cookies:
            name, attrs, redacted = parse_set_cookie(raw)
            if not name or (name, set_url) in seen:
                continue
            seen.add((name, set_url))
            over_https = set_url.lower().startswith("https://")
            session_like = bool(SESSION_COOKIE_RE.search(name))
            missing, severities = [], []

            if "httponly" not in attrs:
                missing.append("HttpOnly")
                severities.append("Medium" if session_like else "Low")
            if over_https and "secure" not in attrs:
                missing.append("Secure")
                severities.append("Medium" if session_like else "Low")
            samesite = attrs.get("samesite", "").lower()
            if not samesite:
                missing.append("SameSite")
                severities.append("Low" if session_like else "Informational")
            elif samesite == "none" and "secure" not in attrs:
                missing.append("Secure (required with SameSite=None)")
                severities.append("Medium")
            if name.startswith(("__Host-", "__Secure-")) and "secure" not in attrs:
                missing.append("Secure (required by cookie prefix)")
                severities.append("Medium")

            if missing:
                ctx.add("cookie-flags", f"Cookie '{name}' is missing security attributes: {', '.join(missing)}",
                        _worst(severities), "confirmed",
                        "Missing cookie attributes make theft (XSS), interception (plain HTTP) or cross-site "
                        "request forgery easier." + (" This cookie name looks like a session/auth cookie." if session_like else ""),
                        f"Set-Cookie: {redacted}", "A07" if session_like else "A02",
                        "Set HttpOnly, Secure and SameSite=Lax (or Strict) on the cookie.", set_url)

    # -- 4. information disclosure
    def _check_info_disclosure(self, ctx: ScanContext) -> None:
        h = ctx.home.headers
        server = h.get("Server", "").strip()
        if server:
            if VERSION_RE.search(server):
                ctx.add("info-server", "Server header discloses software version", "Low", "confirmed",
                        "Exact versions help attackers pick known exploits.", f"Server: {server[:120]}", "A02",
                        "Hide version details (for example ServerTokens Prod in Apache, server_tokens off in nginx).")
            else:
                ctx.add("info-server", "Server header reveals the web server type", "Informational", "confirmed",
                        "The server software name is visible to anyone.", f"Server: {server[:120]}", "A02",
                        "Consider removing or genericising the Server header.")
        for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Runtime"):
            value = h.get(name, "").strip()
            if value:
                ctx.add(f"info-{name.lower()}", f"{name} header discloses technology", "Low", "confirmed",
                        "Technology and version details help attackers target known weaknesses.",
                        f"{name}: {value[:120]}", "A02", f"Remove the {name} header from responses.")
        if ctx.soup is not None:
            meta = ctx.soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
            content = (meta.get("content") or "").strip() if meta else ""
            if content:
                sev = "Low" if VERSION_RE.search(content) else "Informational"
                ctx.add("info-generator", "HTML generator meta tag discloses software", sev, "confirmed",
                        "The page advertises the CMS/framework it was built with.",
                        f'<meta name="generator" content="{content[:120]}">', "A02",
                        "Remove the generator meta tag (or at least its version number).")

    # -- 5. HTML: forms, mixed content, SRI
    def _check_html(self, ctx: ScanContext) -> None:
        if ctx.soup is None:
            ctx.not_completed("html", "HTML analysis (forms, mixed content, SRI)",
                              f"Response is not HTML (Content-Type: {ctx.home.content_type or 'unknown'}).")
            return
        self._analyse_forms(ctx)
        self._analyse_resources(ctx)

    def _analyse_forms(self, ctx: ScanContext) -> None:
        forms = ctx.soup.find_all("form")[:20]
        if not forms:
            return
        page_http = not ctx.is_https
        password_forms, csrf_missing = 0, []
        for form in forms:
            method = (form.get("method") or "GET").strip().upper()
            action_raw = (form.get("action") or "").strip()
            action = urljoin(ctx.final_url, action_raw) if action_raw else ctx.final_url
            action_parts = urlsplit(action)
            if action_parts.scheme not in ("http", "https"):
                continue
            has_password = form.find("input", attrs={"type": re.compile(r"^password$", re.I)}) is not None
            names = [(i.get("name") or "") for i in form.find_all("input")]
            evidence = f"form action={action[:200]}; method={method}; page={ctx.final.scheme}"

            if has_password:
                password_forms += 1
                if action_parts.scheme == "http":
                    ctx.add("form-password-http", "Password form submits credentials over unencrypted HTTP", "High",
                            "confirmed", "Credentials sent over HTTP can be read by anyone on the network path.",
                            evidence, "A04", "Serve the page over HTTPS and submit the form to an https:// action.")
                elif page_http:
                    ctx.add("form-password-http-page", "Password form is served over unencrypted HTTP", "Medium",
                            "confirmed", "A network attacker can modify the page and redirect the credentials.",
                            evidence, "A04", "Serve every page that contains a login form over HTTPS only.")
                if method == "GET":
                    ctx.add("form-password-get", "Password field in a form that uses GET", "High", "confirmed",
                            "Credentials end up in URLs, browser history and server logs.", evidence, "A04",
                            'Use method="POST" for any form that contains a password field.')
                if action_parts.hostname and action_parts.hostname != ctx.final.hostname:
                    ctx.add("form-password-cross-origin", "Password form posts to a different origin", "Medium",
                            "potential", "Credentials are sent to another host; verify it is trusted.", evidence,
                            "A07", "Post login forms to the same origin, or confirm the third party is trusted.")
            if method == "POST" and not any(CSRF_FIELD_RE.search(n) for n in names):
                csrf_missing.append(f"{action[:100]} (POST)")

        ctx.add("form-inventory", "HTML forms detected", "Informational", "confirmed",
                "Inventory of forms found on the scanned page (single page only, no crawling).",
                f"{len(forms)} form(s), {password_forms} with a password field.", "A06",
                "Review each form for transport security, CSRF protection and input validation.")
        if csrf_missing:
            ctx.add("form-csrf", "POST form without a visible anti-CSRF token", "Low", "potential",
                    "No hidden token field was found. Frameworks may protect forms differently "
                    "(for example SameSite cookies or custom headers), so verify manually.",
                    "; ".join(csrf_missing[:3]), "A01",
                    "Add a per-session anti-CSRF token to state-changing forms and set SameSite on session cookies.")
        cache = (ctx.home.headers.get("Cache-Control", "") + " " + ctx.home.headers.get("Pragma", "")).lower()
        if password_forms and "no-store" not in cache:
            ctx.add("form-cache", "Page with password form may be cached", "Low", "potential",
                    "Without Cache-Control: no-store, browsers or proxies may keep copies of sensitive pages.",
                    f"Cache-Control: {ctx.home.headers.get('Cache-Control', '(absent)')[:100]}", "A02",
                    "Send Cache-Control: no-store on pages that contain login forms or personal data.")

    def _analyse_resources(self, ctx: ScanContext) -> None:
        soup, host = ctx.soup, ctx.final.hostname

        if ctx.is_https:
            active, passive = [], []
            for tag, attr in (("script", "src"), ("iframe", "src"), ("link", "href"), ("img", "src")):
                for node in soup.find_all(tag):
                    value = (node.get(attr) or "").strip()
                    if not value.lower().startswith("http://"):
                        continue
                    if tag == "link" and "stylesheet" not in " ".join(node.get("rel") or []).lower():
                        continue
                    (passive if tag == "img" else active).append(f"<{tag}> {value[:120]}")
            if active:
                ctx.add("mixed-active", "Mixed content: insecure scripts, frames or styles on an HTTPS page", "Medium",
                        "confirmed", "Active content loaded over HTTP can be tampered with, undermining HTTPS.",
                        "; ".join(active[:5]), "A02", "Load every sub-resource over HTTPS.")
            if passive:
                ctx.add("mixed-passive", "Mixed content: images loaded over HTTP on an HTTPS page", "Low", "confirmed",
                        "Insecure images can leak browsing details and be replaced.", "; ".join(passive[:5]), "A02",
                        "Load every sub-resource over HTTPS.")

        no_sri = []
        for tag, attr in (("script", "src"), ("link", "href")):
            for node in soup.find_all(tag):
                value = (node.get(attr) or "").strip()
                if tag == "link" and "stylesheet" not in " ".join(node.get("rel") or []).lower():
                    continue
                if not value.startswith(("http://", "https://", "//")):
                    continue
                other = urlsplit(urljoin(ctx.final_url, value)).hostname
                if other and other != host and not node.get("integrity"):
                    no_sri.append(f"<{tag}> {value[:120]}")
        if no_sri:
            ctx.add("sri-missing", "External scripts or styles loaded without Subresource Integrity", "Low", "potential",
                    "If the third-party host is compromised, malicious code would run on this site.",
                    f"{len(no_sri)} resource(s), e.g. " + "; ".join(no_sri[:3]), "A08",
                    'Add integrity="sha384-..." and crossorigin="anonymous" to third-party resources, or self-host them.')

    # -- 6. HTTP methods
    def _check_methods(self, ctx: ScanContext) -> None:
        options = self.client.request("OPTIONS", ctx.final_url, follow_redirects=False, max_bytes=2048)
        allow = options.headers.get("Allow", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(methods & RISKY_METHODS)
        if risky:
            ctx.add("http-methods", "Potentially risky HTTP methods advertised", "Low", "potential",
                    "The Allow header lists methods that are rarely needed on public sites. "
                    "Advertising a method does not prove it is usable.", f"Allow: {allow[:150]}", "A02",
                    "Disable methods that the application does not need.")
        trace = self.client.request("TRACE", ctx.final_url, follow_redirects=False, max_bytes=4096)
        if trace.status == 200 and trace.body[:5].upper() == b"TRACE":
            ctx.add("http-trace", "HTTP TRACE method is enabled", "Medium", "confirmed",
                    "TRACE echoes requests back and can aid cross-site tracing attacks.",
                    "TRACE request returned HTTP 200 with the request echoed in the body.", "A02",
                    "Disable the TRACE method in the web server configuration.")

    # -- 7. exposure
    def _check_exposure(self, ctx: ScanContext) -> None:
        origin = origin_of(ctx.final_url)
        problems = 0

        def fetch(path: str) -> Optional[FetchResult]:
            nonlocal problems
            try:
                return self.client.request("GET", origin + path, follow_redirects=False, max_bytes=65536)
            except (ScanTimeout, RequestBudgetExceeded):
                raise
            except (FetchError, UnsafeTargetError, ResolutionError):
                problems += 1
                return None

        # Homepage par directory listing
        if DIR_LISTING_RE.search(ctx.home.text[:20000]):
            self._listing_finding(ctx, ctx.final_url)

        # Baseline: ek na-maujood path - soft-404 aur verbose error pages pakadne ke liye
        baseline = fetch("/" + secrets.token_hex(8) + "-scanner-check")
        baseline_body = baseline.body if baseline else b""
        if baseline is not None:
            text = baseline.text[:20000]
            for pattern, label in ERROR_SIGNATURES:
                if pattern.search(text):
                    ctx.add("error-disclosure", "Verbose error message or stack trace disclosed", "Medium", "confirmed",
                            "Detailed errors reveal internal paths, frameworks or queries.",
                            f"A request for a non-existent URL returned {label} (HTTP {baseline.status}).", "A10",
                            "Show generic error pages to users and log details server-side only.", baseline.final_url)
                    break

        try:
            for path, title, severity, validator, signature in SENSITIVE_PATHS:
                response = fetch(path)
                if response is None or response.status != 200 or not response.body:
                    continue
                if baseline_body and validator(baseline_body):
                    continue  # baseline par bhi match = false positive
                if validator(response.body):
                    ctx.add("exposed-file", title, severity, "confirmed",
                            "A sensitive file is publicly downloadable.",
                            f"GET {path} returned HTTP 200 and the content matches {signature} ({TRACKING_NOTE}).",
                            "A02", REMEDIATION["expose"], origin + path)

            for path in LISTING_PATHS:
                response = fetch(path)
                if response and response.status == 200 and DIR_LISTING_RE.search(response.text[:20000]):
                    self._listing_finding(ctx, origin + path)
        except RequestBudgetExceeded as exc:
            ctx.not_completed("exposure-budget", "remaining file/directory probes", str(exc))

        if problems:
            ctx.not_completed("exposure-errors", "some file/directory probes",
                              f"{problems} probe request(s) failed (timeout or connection error); results may be incomplete.")

    def _listing_finding(self, ctx: ScanContext, url: str) -> None:
        ctx.add("dir-listing", "Directory listing is enabled", "Medium", "confirmed",
                "Visitors can browse the files in this directory.",
                "Response body contains an 'Index of' / 'Directory listing' page.", "A02",
                "Disable directory indexing (Options -Indexes in Apache, autoindex off in nginx).", url)

    # -- scope notes (hamesha add hote hain)
    def _add_scope_notes(self, ctx: ScanContext) -> None:
        url = ctx.final_url or ctx.target.url
        ctx.add("scan-scope", "Scan scope and limitations", "Informational", "confirmed",
                "This was a limited, non-intrusive scan of one URL and a short list of well-known paths. "
                "A report with few or no findings does NOT mean the website is secure.",
                f"{self.client.requests_made} HTTP request(s) sent by the built-in scanner.", "A02",
                "Combine automated scanning with manual testing and code review.", url)
        ctx.add("not-implemented", "Checks not performed by the built-in scanner", "Informational", "not_completed",
                "These areas are NOT tested by the Python checks: injection (SQLi/XSS), authentication and "
                "authorization testing, access-control testing, business logic, JavaScript-rendered content, "
                "authenticated pages, full-site crawling and known-CVE detection for third-party components.",
                "Not implemented in the built-in scanner. OWASP ZAP (if connected) covers some of these.", "A06",
                "Use the optional ZAP scan and manual testing for these areas.", url)
