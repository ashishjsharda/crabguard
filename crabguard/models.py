"""
CrabGuard – Core Data Models
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ScanMode(str, Enum):
    PASSIVE = "passive"   # No active probing
    ACTIVE  = "active"    # Full active pentest
    FULL    = "full"      # Passive + active


SEVERITY_SCORE: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH:     10,
    Severity.MEDIUM:    5,
    Severity.LOW:       2,
    Severity.INFO:      0,
}

OWASP_MAP = {
    "security_headers":   "A05:2021 – Security Misconfiguration",
    "cookies":            "A02:2021 – Cryptographic Failures",
    "tls":                "A02:2021 – Cryptographic Failures",
    "content":            "A08:2021 – Software & Data Integrity Failures",
    "disclosure":         "A05:2021 – Security Misconfiguration",
    "injection":          "A03:2021 – Injection",
    "xss":                "A03:2021 – Injection (XSS)",
    "redirect":           "A01:2021 – Broken Access Control",
    "ssrf":               "A10:2021 – Server-Side Request Forgery",
    "discovery":          "A05:2021 – Security Misconfiguration",
    "auth":               "A07:2021 – Identification & Auth Failures",
}


@dataclass
class Finding:
    title:       str
    description: str
    severity:    Severity
    category:    str                        # matches OWASP_MAP key
    remediation: str         = ""
    evidence:    str         = ""
    url:         str         = ""
    cwe:         str         = ""
    references:  List[str]   = field(default_factory=list)

    @property
    def owasp(self) -> str:
        return OWASP_MAP.get(self.category, "")

    @property
    def severity_color(self) -> str:
        return {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH:     "#ef4444",
            Severity.MEDIUM:   "#f59e0b",
            Severity.LOW:      "#3b82f6",
            Severity.INFO:     "#64748b",
        }[self.severity]

    @property
    def severity_bg(self) -> str:
        return {
            Severity.CRITICAL: "#fef2f2",
            Severity.HIGH:     "#fef2f2",
            Severity.MEDIUM:   "#fffbeb",
            Severity.LOW:      "#eff6ff",
            Severity.INFO:     "#f8fafc",
        }[self.severity]


@dataclass
class CategoryResult:
    name:     str
    score:    int          # 0-100
    findings: List[Finding] = field(default_factory=list)
    passed:   int          = 0
    warned:   int          = 0
    failed:   int          = 0

    @property
    def status(self) -> str:
        if self.score >= 80:
            return "PASS"
        if self.score >= 50:
            return "WARN"
        return "FAIL"

    @property
    def status_color(self) -> str:
        return {"PASS": "#10b981", "WARN": "#f59e0b", "FAIL": "#ef4444"}[self.status]


@dataclass
class ScanReport:
    target:        str
    scan_mode:     ScanMode
    started_at:    datetime
    completed_at:  datetime
    categories:    List[CategoryResult]    = field(default_factory=list)
    scanner_version: str                   = "1.0.0"

    @property
    def all_findings(self) -> List[Finding]:
        findings = []
        for cat in self.categories:
            findings.extend(cat.findings)
        return findings

    @property
    def overall_score(self) -> int:
        if not self.categories:
            return 100
        return round(sum(c.score for c in self.categories) / len(self.categories))

    @property
    def score_label(self) -> str:
        s = self.overall_score
        if s >= 90: return "Excellent Security"
        if s >= 75: return "Good Security"
        if s >= 50: return "Moderate Risk"
        if s >= 25: return "High Risk"
        return "Critical Risk"

    @property
    def score_color(self) -> str:
        s = self.overall_score
        if s >= 75: return "#10b981"
        if s >= 50: return "#f59e0b"
        return "#ef4444"

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.LOW)

    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()

    def owasp_coverage(self) -> dict:
        owasp_items = {
            "A01:2021 – Broken Access Control":              "N/A",
            "A02:2021 – Cryptographic Failures":             "N/A",
            "A03:2021 – Injection (incl. XSS)":              "N/A",
            "A04:2021 – Insecure Design":                    "N/A",
            "A05:2021 – Security Misconfiguration":          "N/A",
            "A06:2021 – Vulnerable & Outdated Components":   "N/A",
            "A07:2021 – Identification & Auth Failures":     "N/A",
            "A08:2021 – Software & Data Integrity Failures": "N/A",
            "A09:2021 – Security Logging & Monitoring":      "N/A",
            "A10:2021 – Server-Side Request Forgery":        "N/A",
        }
        for f in self.all_findings:
            owasp = f.owasp
            for key in owasp_items:
                if owasp and owasp[:4] == key[:4]:
                    current = owasp_items[key]
                    if f.severity in (Severity.CRITICAL, Severity.HIGH):
                        owasp_items[key] = "FAIL"
                    elif f.severity == Severity.MEDIUM and current != "FAIL":
                        owasp_items[key] = "WARN"
                    elif current == "N/A":
                        owasp_items[key] = "PASS"
        return owasp_items
