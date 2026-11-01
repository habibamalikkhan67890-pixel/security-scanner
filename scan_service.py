"""scan_service.py - background scan execution (ThreadPoolExecutor).

Concurrency limit: max_concurrent_scans threads + max_queued_scans queue. Isse server resources
exhaust nahi hote. Har scan ka overall timeout hota hai (Deadline).
"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional

from database import Database, DatabaseError, utcnow
from http_client import Deadline, SafeHttpClient, ScanTimeout
from models import Finding
from scanner import ScanOutcome, SecurityScanner, TargetUnreachable
from security import InvalidURLError, ResolutionError, TargetPolicy, UnsafeTargetError
from zap_client import ZapClient, ZapError, ZapUnavailable

logger = logging.getLogger(__name__)


class ServiceBusy(Exception):
    """Queue full hai - baad mein try karein."""


class ScanService:
    def __init__(self, settings, db: Database, zap_factory: Optional[Callable[[], ZapClient]] = None):
        self.settings = settings
        self.db = db
        self._zap_factory = zap_factory or (
            lambda: ZapClient(settings.zap_url, settings.zap_api_key, settings.zap_timeout))
        self._executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_scans, thread_name_prefix="scan")
        self._lock = threading.Lock()
        self._pending = 0
        self.policy = TargetPolicy(allow_lab=settings.allow_lab_targets, allowed_ports=settings.allowed_ports)

    # ---------------------------------------------------------------- public
    def zap_status(self) -> dict:
        return self._zap_factory().status()

    def submit(self, scan_id: int) -> None:
        capacity = self.settings.max_concurrent_scans + self.settings.max_queued_scans
        with self._lock:
            if self._pending >= capacity:
                raise ServiceBusy("The scanner is busy. Please wait for running scans to finish and try again.")
            self._pending += 1
        self._executor.submit(self._run_wrapper, scan_id)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    # ---------------------------------------------------------------- internals
    def _run_wrapper(self, scan_id: int) -> None:
        try:
            self._run(scan_id)
        except Exception:   # last line of defence - thread kabhi silently marr na jaye
            logger.exception("Unexpected error in scan %s", scan_id)
            self._safe_update(scan_id, status="failed", error="Internal error while running the scan.",
                              finished_at=utcnow())
        finally:
            with self._lock:
                self._pending -= 1

    def _safe_update(self, scan_id: int, **fields) -> None:
        try:
            self.db.update_scan(scan_id, **fields)
        except (DatabaseError, ValueError):
            logger.exception("Could not update scan %s", scan_id)

    def _run(self, scan_id: int) -> None:
        scan = self.db.get_scan(scan_id)
        if scan is None:   # user ne queue mein hote hue delete kar diya
            return
        self.db.update_scan(scan_id, status="running", started_at=utcnow(), progress=1,
                            current_step="Starting")
        deadline = Deadline(self.settings.scan_timeout)
        client = SafeHttpClient(self.settings, deadline, self.policy)

        def progress(pct: int, step: str) -> None:
            self._safe_update(scan_id, progress=max(0, min(100, int(pct))), current_step=step[:120],
                              requests_made=client.requests_made)

        findings: List[Finding] = []
        status, error, zap_status, zap_message = "completed", None, "not_requested", None
        try:
            # ZAP ke saath ho to Python checks progress bar ka pehla 60% lete hain
            scale = 0.6 if scan["use_zap"] else 1.0
            scanner = SecurityScanner(self.settings, deadline, lambda p, s: progress(int(p * scale), s), client)
            outcome: ScanOutcome = scanner.run(scan["target_url"])
            findings.extend(outcome.findings)
            if outcome.timed_out:
                status, error = "timeout", "Scan time limit reached; results are partial."

            if scan["use_zap"] and not outcome.timed_out:
                zap_status, zap_message, zap_findings = self._run_zap(scan, deadline, progress)
                findings.extend(zap_findings)
                if zap_status == "timeout":
                    status, error = "timeout", "Scan time limit reached during the ZAP scan; results are partial."
        except TargetUnreachable as exc:
            status, error = "failed", str(exc)
            findings.append(Finding(
                check_id="target-unreachable", title="Check not completed: target could not be scanned",
                severity="Informational", status="not_completed", url=scan["target_url"],
                description="The scanner could not fetch the target, so no checks were run.",
                evidence=str(exc), owasp="N/A",
                remediation="Check the URL, that the site is online and publicly reachable, and the SSRF policy "
                            "(private/loopback addresses are blocked unless lab mode is enabled)."))
        except ScanTimeout:
            status, error = "timeout", "Scan time limit reached; results are partial."
        except (UnsafeTargetError, InvalidURLError, ResolutionError) as exc:
            status, error = "failed", str(exc)
        except Exception:
            logger.exception("Scan %s failed", scan_id)
            status, error = "failed", "Internal error while running the scan."
        finally:
            client.close()

        try:
            self.db.add_findings(scan_id, findings)
        except DatabaseError:
            logger.exception("Could not save findings for scan %s", scan_id)
            status, error = "failed", "Could not save scan results to the database."
        self._safe_update(scan_id, status=status, error=error, progress=100,
                          current_step="Finished" if status == "completed" else status.capitalize(),
                          zap_status=zap_status, zap_message=zap_message,
                          requests_made=client.requests_made, finished_at=utcnow())

    def _run_zap(self, scan: dict, deadline: Deadline, progress):
        """(zap_status, message, findings) wapas karta hai. ZAP down ho to sirf not_completed finding."""
        active = bool(scan["active_scan"])
        url = scan["target_url"]
        if active and not (self.settings.zap_active_enabled and scan["authorization_confirmed"]):
            msg = "Active scan was requested but is disabled (ZAP_ACTIVE_ENABLED=false) or not authorized."
            return "skipped", msg, [self._zap_not_completed(url, msg)]
        try:
            zap = self._zap_factory()
            findings = zap.run_scan(url, active=active, settings=self.settings, deadline=deadline,
                                    progress=lambda p, s: progress(60 + int(p * 0.4), s),
                                    scan_label=str(scan["id"]))
            return "completed", f"ZAP {'active' if active else 'passive'} scan finished.", findings
        except ZapUnavailable as exc:
            return "unavailable", str(exc), [self._zap_not_completed(url, str(exc))]
        except ScanTimeout:
            msg = "Scan time limit reached while ZAP was running; ZAP results are partial or missing."
            return "timeout", msg, [self._zap_not_completed(url, msg)]
        except ZapError as exc:
            return "error", str(exc), [self._zap_not_completed(url, str(exc))]

    @staticmethod
    def _zap_not_completed(url: str, reason: str) -> Finding:
        return Finding(
            check_id="zap-not-completed", title="Check not completed: OWASP ZAP scan",
            severity="Informational", status="not_completed", url=url,
            description="The optional OWASP ZAP scan did not run or did not finish. "
                        "Only the built-in Python checks produced results for this scan.",
            evidence=reason, owasp="N/A",
            remediation="Start ZAP in daemon mode, check ZAP_URL / ZAP_API_KEY on the Scanner page, then re-run.",
            source="zap")
