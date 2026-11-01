"""zap_client.py - OWASP ZAP ke documented REST API ke zariye integration.

ZAP ko alag se install/run karna padta hai (daemon mode). Agar ZAP available nahi to yeh module
ZapUnavailable raise karta hai aur scan_service sirf Python checks ke saath aage barh jata hai.
Yahan kabhi simulated/fake findings nahi banti - sirf wahi alerts jo ZAP khud report kare.

Mode:
  passive (default) : limited spider + ZAP ka passive scanner (koi attack payload nahi)
  active (optional) : ZAP active scan - sirf explicit authorization + ZAP_ACTIVE_ENABLED=true par
"""
import logging
import re
import time
import uuid
from typing import Callable, Dict, List, Optional
from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup

from http_client import Deadline
from models import OWASP, Finding

logger = logging.getLogger(__name__)

RISK_TO_SEVERITY = {"High": "High", "Medium": "Medium", "Low": "Low", "Informational": "Informational"}
MAX_ALERTS = 300
_OWASP_URL = re.compile(r"A(\d{2})_(\d{4})-([A-Za-z_]+)")


class ZapError(Exception):
    """ZAP API ne error diya."""


class ZapUnavailable(ZapError):
    """ZAP tak pahunch nahi sakte ya API key ghalat hai."""


class ZapClient:
    POLL_INTERVAL = 1.0   # ZAP status poll gap (seconds); tests ise chhota kar dete hain

    def __init__(self, base_url: str, api_key: str = "", timeout: float = 10.0,
                 session: Optional[requests.Session] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.trust_env = False   # ZAP local hai; system proxy use nahi karna

    # ---------------------------------------------------------------- low level
    def _call(self, component: str, kind: str, name: str, params: Optional[Dict] = None) -> Dict:
        """ZAP API call: /JSON/<component>/<view|action>/<name>/ . API key header mein jati hai."""
        url = f"{self.base_url}/JSON/{component}/{kind}/{name}/"
        headers = {"X-ZAP-API-Key": self.api_key} if self.api_key else {}
        try:
            response = self.session.get(url, params=params or {}, headers=headers, timeout=self.timeout)
        except requests.exceptions.ConnectionError as exc:
            raise ZapUnavailable(
                f"Cannot connect to ZAP at {self.base_url}. Start ZAP in daemon mode and check ZAP_URL."
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise ZapUnavailable(f"ZAP at {self.base_url} did not answer within {self.timeout:.0f}s.") from exc
        except requests.exceptions.RequestException as exc:
            raise ZapUnavailable(f"ZAP request failed: {exc}") from exc

        try:
            data = response.json()
        except ValueError:
            data = {}
        code = data.get("code") if isinstance(data, dict) else None
        if code in ("bad_api_key", "disabled_api") or response.status_code in (401, 403):
            raise ZapUnavailable("ZAP rejected the API key. Set ZAP_API_KEY to the key ZAP was started with.")
        if response.status_code >= 400:
            message = data.get("message") if isinstance(data, dict) else None
            raise ZapError(f"ZAP API error {response.status_code} on {component}/{name}: {message or 'unknown error'}")
        return data if isinstance(data, dict) else {}

    # ---------------------------------------------------------------- status
    def status(self) -> Dict:
        """UI ke liye connection status: {connected, version, error}."""
        try:
            version = self._call("core", "view", "version").get("version", "unknown")
            return {"connected": True, "version": version, "error": None, "url": self.base_url}
        except ZapError as exc:
            return {"connected": False, "version": None, "error": str(exc), "url": self.base_url}

    # ---------------------------------------------------------------- scanning
    def run_scan(self, target_url: str, *, active: bool, settings, deadline: Deadline,
                 progress: Callable[[int, str], None], scan_label: str = "scan") -> List[Finding]:
        """Poora ZAP flow chalata hai aur ZAP ke asli alerts ko Finding mein convert karta hai."""
        parts = urlsplit(target_url)
        origin = f"{parts.scheme}://{parts.netloc}"
        context_name = f"secscan-{scan_label}-{uuid.uuid4().hex[:6]}"
        context_id = None

        self._call("core", "view", "version")   # connection/API key pehle verify
        try:
            if settings.zap_new_session_per_scan:
                self._call("core", "action", "newSession", {"name": "", "overwrite": "true"})

            result = self._call("context", "action", "newContext", {"contextName": context_name})
            context_id = result.get("contextId")
            self._call("context", "action", "includeInContext", {
                "contextName": context_name, "regex": "^" + re.escape(origin) + "(/.*)?$"})

            # Limits set karna (scope, depth, threads, delay)
            self._call("spider", "action", "setOptionMaxDepth", {"Integer": settings.zap_spider_max_depth})
            self._call("spider", "action", "setOptionMaxDuration", {"Integer": settings.zap_spider_max_minutes})
            self._call("spider", "action", "setOptionThreadCount", {"Integer": settings.zap_threads})

            progress(10, "ZAP: accessing target")
            self._call("core", "action", "accessUrl", {"url": target_url, "followRedirects": "true"})
            deadline.check()

            progress(20, "ZAP: spidering (limited)")
            scan = self._call("spider", "action", "scan", {
                "url": target_url, "maxChildren": settings.zap_spider_max_children, "recurse": "true",
                "contextName": context_name, "subtreeOnly": "true"})
            spider_id = scan.get("scan")
            self._wait_percent(
                lambda: self._call("spider", "view", "status", {"scanId": spider_id}).get("status"),
                deadline, settings.zap_spider_max_minutes * 60,
                lambda: self._call("spider", "action", "stop", {"scanId": spider_id}),
                lambda pct: progress(20 + pct // 5, "ZAP: spidering (limited)"),
            )

            progress(45, "ZAP: waiting for passive scan")
            self._wait_zero(lambda: self._call("pscan", "view", "recordsToScan").get("recordsToScan"),
                            deadline, 120)

            if active:
                if not settings.zap_active_enabled:
                    raise ZapError("Active scan is disabled (ZAP_ACTIVE_ENABLED=false).")
                # setOptionDelayInMs ZAP docs mein deprecated hai (naye versions mein hat sakta hai):
                # fail ho to scan nahi rukta, thread/duration limits phir bhi lagti hain.
                try:
                    self._call("ascan", "action", "setOptionDelayInMs", {"Integer": settings.zap_active_delay_ms})
                except ZapUnavailable:
                    raise
                except ZapError as exc:
                    logger.warning("Could not set ZAP active scan delay (%s); continuing with other limits.", exc)
                self._call("ascan", "action", "setOptionThreadPerHost", {"Integer": settings.zap_threads})
                self._call("ascan", "action", "setOptionMaxScanDurationInMins",
                           {"Integer": settings.zap_active_max_minutes})
                progress(55, "ZAP: active scan (authorized targets only)")
                params = {"url": target_url, "recurse": "true", "inScopeOnly": "true"}
                if context_id:
                    params["contextId"] = context_id
                started = self._call("ascan", "action", "scan", params)
                ascan_id = started.get("scan")
                self._wait_percent(
                    lambda: self._call("ascan", "view", "status", {"scanId": ascan_id}).get("status"),
                    deadline, settings.zap_active_max_minutes * 60 + 30,
                    lambda: self._call("ascan", "action", "stop", {"scanId": ascan_id}),
                    lambda pct: progress(55 + int(pct * 0.35), "ZAP: active scan (authorized targets only)"),
                )

            progress(92, "ZAP: collecting alerts")
            return self._collect_alerts(origin)
        finally:
            if context_name:
                try:
                    self._call("context", "action", "removeContext", {"contextName": context_name})
                except ZapError:
                    logger.warning("Could not remove ZAP context %s", context_name)

    @staticmethod
    def _wait_percent(get_status, deadline: Deadline, max_seconds: float, stop, on_progress) -> None:
        end = time.monotonic() + max_seconds
        while True:
            deadline.check()
            try:
                percent = int(get_status())
            except (TypeError, ValueError):
                raise ZapError("ZAP returned an unexpected scan status.")
            on_progress(percent)
            if percent >= 100:
                return
            if time.monotonic() > end:
                try:
                    stop()   # ZAP scan ko limit par rok do
                except ZapError:
                    pass
                return
            time.sleep(ZapClient.POLL_INTERVAL)

    @staticmethod
    def _wait_zero(get_count, deadline: Deadline, max_seconds: float) -> None:
        end = time.monotonic() + max_seconds
        while time.monotonic() < end:
            deadline.check()
            try:
                if int(get_count()) == 0:
                    return
            except (TypeError, ValueError):
                return
            time.sleep(ZapClient.POLL_INTERVAL)

    def _alerts_page(self, origin: str, start: int, count: int) -> Dict:
        """Naya 'alert' component use karta hai; purane ZAP par deprecated core/view/alerts par fallback."""
        params = {"baseurl": origin, "start": start, "count": count}
        try:
            return self._call("alert", "view", "alerts", params)
        except ZapUnavailable:
            raise
        except ZapError:
            return self._call("core", "view", "alerts", params)

    def _collect_alerts(self, origin: str) -> List[Finding]:
        findings: List[Finding] = []
        start, page = 0, 100
        while start < MAX_ALERTS * 3:
            data = self._alerts_page(origin, start, page)
            alerts = data.get("alerts", [])
            for alert in alerts:
                finding = alert_to_finding(alert)
                if finding is not None:
                    findings.append(finding)
            if len(alerts) < page:
                break
            start += page
        # duplicate (same title + url) hata do aur cap lagao
        unique, seen = [], set()
        for f in findings:
            key = (f.title, f.url)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique[:MAX_ALERTS]


def _strip_html(value: str) -> str:
    if not value:
        return ""
    return BeautifulSoup(value, "html.parser").get_text(" ", strip=True)


def owasp_from_tags(tags) -> str:
    """ZAP alert tags se OWASP Top 10 category nikalta hai (2025 ko 2021 par preference)."""
    if not isinstance(tags, dict):
        return "Not mapped by ZAP"
    best = None
    for key, url in tags.items():
        if not str(key).upper().startswith("OWASP_"):
            continue
        match = _OWASP_URL.search(str(url))
        if match:
            number, year, slug = match.groups()
            label = f"A{number}:{year} - {slug.replace('_', ' ')}"
            if year == "2025":
                return OWASP.get(f"A{number}", label)
            best = best or label
    return best or "Not mapped by ZAP"


def alert_to_finding(alert: Dict) -> Optional[Finding]:
    risk = alert.get("risk") or alert.get("riskdesc", "").split(" ")[0]
    confidence = alert.get("confidence", "")
    if confidence == "False Positive" or risk not in RISK_TO_SEVERITY:
        return None
    status = "confirmed" if confidence in ("High", "Confirmed") else "potential"
    evidence_bits = []
    if alert.get("evidence"):
        evidence_bits.append(f"Evidence: {alert['evidence']}")
    if alert.get("param"):
        evidence_bits.append(f"Parameter: {alert['param']}")
    if alert.get("attack"):
        evidence_bits.append(f"Attack: {alert['attack']}")
    if alert.get("cweid") and str(alert["cweid"]) not in ("-1", "0"):
        evidence_bits.append(f"CWE-{alert['cweid']}")
    evidence_bits.append(f"ZAP confidence: {confidence or 'unknown'}")
    return Finding(
        check_id=f"zap-{alert.get('pluginId') or alert.get('alertRef') or 'alert'}",
        title=alert.get("alert") or alert.get("name") or "ZAP alert",
        severity=RISK_TO_SEVERITY[risk],
        status=status,
        url=alert.get("url") or "",
        description=_strip_html(alert.get("description", "")),
        evidence="; ".join(evidence_bits),
        owasp=owasp_from_tags(alert.get("tags")),
        remediation=_strip_html(alert.get("solution", "")) or "See the ZAP alert reference.",
        source="zap",
    )
