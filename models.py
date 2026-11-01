"""models.py - Finding ka structure, severity/status constants aur OWASP Top 10:2025 labels.

Severity ki classification transparent rakhi gayi hai (about page aur README mein likhi hai).
Status teen hi ho sakte hain:
  confirmed     - response mein seedha observe hua (ya ZAP ne High/Confirmed confidence di)
  potential     - heuristic indicator, manual verification chahiye
  not_completed - check chal nahi saka ya implement nahi hai (reason evidence mein)
"""
import re
from dataclasses import asdict, dataclass
from typing import Dict

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}  # chhota number = zyada serious
STATUSES = ("confirmed", "potential", "not_completed")
SOURCES = ("python", "zap")

# OWASP Top 10:2025 (owasp.org/Top10) ke labels
OWASP = {
    "A01": "A01:2025 - Broken Access Control",
    "A02": "A02:2025 - Security Misconfiguration",
    "A03": "A03:2025 - Software Supply Chain Failures",
    "A04": "A04:2025 - Cryptographic Failures",
    "A05": "A05:2025 - Injection",
    "A06": "A06:2025 - Insecure Design",
    "A07": "A07:2025 - Authentication Failures",
    "A08": "A08:2025 - Software or Data Integrity Failures",
    "A09": "A09:2025 - Security Logging and Alerting Failures",
    "A10": "A10:2025 - Mishandling of Exceptional Conditions",
}

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value, limit: int = 600) -> str:
    """Evidence/description ko safe aur chhota rakhta hai (control chars hata kar truncate)."""
    text = "" if value is None else str(value)
    text = _CONTROL_CHARS.sub("", text).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    status: str
    url: str
    description: str
    evidence: str
    owasp: str
    remediation: str
    source: str = "python"

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity!r}")
        if self.status not in STATUSES:
            raise ValueError(f"Invalid status: {self.status!r}")
        if self.source not in SOURCES:
            raise ValueError(f"Invalid source: {self.source!r}")
        self.title = clean_text(self.title, 200)
        self.url = clean_text(self.url, 2048)
        self.description = clean_text(self.description, 1200)
        self.evidence = clean_text(self.evidence, 800)
        self.owasp = clean_text(self.owasp, 200)
        self.remediation = clean_text(self.remediation, 1200)

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)
