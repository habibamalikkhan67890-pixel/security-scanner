"""database.py - SQLite storage (scans + findings).

Saari queries parameterized hain (SQL injection se bachav). Column names sirf whitelist se aate hain.
Passwords/API keys/cookie values kabhi store nahi hoti.
"""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from models import SEVERITIES, Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url        TEXT NOT NULL,
    host              TEXT NOT NULL,
    mode              TEXT NOT NULL DEFAULT 'basic',
    use_zap           INTEGER NOT NULL DEFAULT 0,
    active_scan       INTEGER NOT NULL DEFAULT 0,
    authorization_confirmed INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL DEFAULT 'queued',
    progress          INTEGER NOT NULL DEFAULT 0,
    current_step      TEXT NOT NULL DEFAULT '',
    error             TEXT,
    zap_status        TEXT NOT NULL DEFAULT 'not_requested',
    zap_message       TEXT,
    requests_made     INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    started_at        TEXT,
    finished_at       TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id     TEXT NOT NULL,
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('Critical','High','Medium','Low','Informational')),
    status       TEXT NOT NULL CHECK (status IN ('confirmed','potential','not_completed')),
    url          TEXT NOT NULL,
    description  TEXT NOT NULL,
    evidence     TEXT NOT NULL,
    owasp        TEXT NOT NULL,
    remediation  TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT 'python',
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
"""

UPDATABLE_SCAN_COLUMNS = {
    "status", "progress", "current_step", "error", "zap_status", "zap_message",
    "requests_made", "started_at", "finished_at",
}
VALID_STATUSES = {"queued", "running", "completed", "failed", "timeout"}


class DatabaseError(Exception):
    """Database operation fail hua (user ko generic message dikhate hain)."""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class Database:
    def __init__(self, path: str):
        self.path = str(path)

    @contextmanager
    def _connect(self):
        conn = None
        try:
            conn = sqlite3.connect(self.path, timeout=15)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            if conn is not None:
                conn.rollback()
            raise DatabaseError(f"Database error: {exc}") from exc
        finally:
            if conn is not None:
                conn.close()

    # ---------------------------------------------------------------- setup
    def init_db(self) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def mark_interrupted(self) -> int:
        """Restart ke baad jo scans queued/running reh gaye unhe failed mark karta hai."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE scans SET status='failed', error=?, finished_at=? WHERE status IN ('queued','running')",
                ("Scan was interrupted because the application restarted.", utcnow()),
            )
            return cur.rowcount

    # ---------------------------------------------------------------- scans
    def create_scan(self, target_url: str, host: str, mode: str, use_zap: bool, active_scan: bool,
                    authorization_confirmed: bool) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (target_url, host, mode, use_zap, active_scan, authorization_confirmed, "
                "status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)",
                (target_url, host, mode, int(use_zap), int(active_scan), int(authorization_confirmed), utcnow()),
            )
            return int(cur.lastrowid)

    def update_scan(self, scan_id: int, **fields) -> None:
        unknown = set(fields) - UPDATABLE_SCAN_COLUMNS
        if unknown:
            raise ValueError(f"Cannot update columns: {sorted(unknown)}")
        if "status" in fields and fields["status"] not in VALID_STATUSES:
            raise ValueError(f"Invalid scan status: {fields['status']!r}")
        if not fields:
            return
        assignments = ", ".join(f"{column} = ?" for column in fields)   # column names whitelist se aaye
        with self._connect() as conn:
            conn.execute(f"UPDATE scans SET {assignments} WHERE id = ?", (*fields.values(), scan_id))

    def get_scan(self, scan_id: int) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            scan = dict(row)
            scan["counts"] = self._counts(conn, scan_id)
            return scan

    def list_scans(self, limit: int = 200, offset: int = 0) -> List[Dict]:
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
            scans = []
            for row in rows:
                scan = dict(row)
                scan["counts"] = self._counts(conn, scan["id"])
                scans.append(scan)
            return scans

    def delete_scan(self, scan_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cur.rowcount > 0

    def delete_all_scans(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scans")
            return cur.rowcount

    # ---------------------------------------------------------------- findings
    def add_findings(self, scan_id: int, findings: Iterable[Finding]) -> None:
        now = utcnow()
        rows = [
            (scan_id, f.check_id, f.title, f.severity, f.status, f.url, f.description, f.evidence,
             f.owasp, f.remediation, f.source, now)
            for f in findings
        ]
        if not rows:
            return
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO findings (scan_id, check_id, title, severity, status, url, description, evidence, "
                "owasp, remediation, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    def get_findings(self, scan_id: int) -> List[Dict]:
        order = "CASE severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)) + " END"
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings WHERE scan_id = ? "
                f"ORDER BY (status = 'not_completed'), {order}, id",
                (scan_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def _counts(conn, scan_id: int) -> Dict[str, int]:
        """not_completed items ko severity count mein nahi ginte (woh vulnerabilities nahi hain)."""
        counts = {s: 0 for s in SEVERITIES}
        counts["not_completed"] = 0
        for row in conn.execute(
            "SELECT severity, status, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity, status",
            (scan_id,),
        ):
            if row["status"] == "not_completed":
                counts["not_completed"] += row["n"]
            else:
                counts[row["severity"]] += row["n"]
        return counts

    # ---------------------------------------------------------------- dashboard
    def dashboard_stats(self, latest: int = 8) -> Dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            by_status = {r["status"]: r["n"] for r in conn.execute(
                "SELECT status, COUNT(*) AS n FROM scans GROUP BY status")}
            severity = {s: 0 for s in SEVERITIES}
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings WHERE status != 'not_completed' GROUP BY severity"
            ):
                severity[row["severity"]] += row["n"]
            latest_rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (latest,)).fetchall()
            latest_scans = []
            for row in latest_rows:
                scan = dict(row)
                scan["counts"] = self._counts(conn, scan["id"])
                latest_scans.append(scan)
        return {
            "total_scans": total,
            "completed_scans": by_status.get("completed", 0),
            "failed_scans": by_status.get("failed", 0) + by_status.get("timeout", 0),
            "running_scans": by_status.get("running", 0) + by_status.get("queued", 0),
            "severity": severity,
            "high_risk": severity["Critical"] + severity["High"],
            "latest_scans": latest_scans,
        }
