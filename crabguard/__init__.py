"""
CrabGuard — Enterprise Web Security Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A Burp Suite + OWASP ZAP alternative that does passive AND active scanning
and generates beautiful branded reports.

Quick start:
    from crabguard import CrabGuardScanner, CrabGuardConfig, ScanMode

    scanner = CrabGuardScanner("https://example.com", verbose=True)
    report  = scanner.scan()
    scanner.save_report(report, "report.html")

Active scanning (you must own / have permission to scan the target):
    config  = CrabGuardConfig(active_consent=True)
    scanner = CrabGuardScanner("https://example.com", mode=ScanMode.FULL, config=config)
    report  = scanner.scan()
    scanner.save_report(report, "report.html", fmt="html")
    scanner.save_report(report, "report.pdf",  fmt="pdf")
    scanner.save_report(report, "report.json", fmt="json")
"""

from .scanner import CrabGuardScanner
from .config  import CrabGuardConfig
from .models  import ScanMode, ScanReport, Finding, Severity, CategoryResult

__version__ = "1.0.1"
__author__  = "CrabGuard Security"

__all__ = [
    "CrabGuardScanner",
    "CrabGuardConfig",
    "ScanMode",
    "ScanReport",
    "Finding",
    "Severity",
    "CategoryResult",
]
