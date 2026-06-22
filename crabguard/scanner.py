"""
CrabGuard – Main Scanner Orchestrator
"""
from __future__ import annotations
import sys
from datetime import datetime
from typing import Optional

from .config import CrabGuardConfig, DEFAULT_CONFIG
from .models import ScanReport, ScanMode
from .licensing import validate, check_feature, LicenseInfo
from .utils.http_client import CrabGuardHTTPClient, normalize_url
from .scanners.passive import headers, cookies, tls, content, disclosure
from .scanners.active  import injection, discovery, redirect


class CrabGuardScanner:
    """
    Main scanner class.

    Usage:
        from crabguard import CrabGuardScanner, CrabGuardConfig, ScanMode

        config  = CrabGuardConfig(active_consent=True)
        scanner = CrabGuardScanner("https://example.com", mode=ScanMode.FULL, config=config)
        report  = scanner.scan()
        report  = scanner.save_report("report.html")
    """

    def __init__(
        self,
        target:  str,
        mode:    ScanMode       = ScanMode.PASSIVE,
        config:  CrabGuardConfig = None,
        verbose: bool           = False,
    ):
        self.target   = normalize_url(target)
        self.mode     = mode
        self.config   = config or DEFAULT_CONFIG
        self.verbose  = verbose
        self.client   = CrabGuardHTTPClient(self.config)
        self.license  = validate(self.config.api_key)

        if self.license.error and self.verbose:
            self._log(f"  ⚠  License: {self.license.error}", error=True)
        elif self.verbose and self.license.is_pro:
            org = f" ({self.license.org})" if self.license.org else ""
            self._log(f"  ✓  Pro license active{org} — all features unlocked")

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> ScanReport:
        """Run the full scan and return a ScanReport."""
        started_at = datetime.utcnow()
        self._log(f"[CrabGuard] Starting {self.mode.value} scan of {self.target}")

        # Initial fetch
        self._log("  → Fetching target...")
        response = self.client.get(self.target)
        if response is None:
            self._log(f"  ✗ Could not reach {self.target}", error=True)
            sys.exit(1)

        self._log(f"  ✓ Got {response.status_code} in {response.elapsed.total_seconds():.2f}s")

        categories = []

        # ── Passive scans (always run) ────────────────────────────────────────
        self._log("  → Running passive scans...")

        self._log("     · Security headers")
        categories.append(headers.scan(response))

        self._log("     · Cookie security")
        categories.append(cookies.scan(response))

        self._log("     · TLS / HTTPS")
        categories.append(tls.scan(self.target, response))

        self._log("     · Content analysis (SRI, forms, JS libs, mixed content)")
        categories.append(content.scan(self.target, response))

        self._log("     · Information disclosure (CORS, fingerprinting)")
        categories.append(disclosure.scan(response))

        # ── Active scans (require consent + Pro key) ──────────────────────────
        if self.mode in (ScanMode.ACTIVE, ScanMode.FULL):
            if not self.config.active_consent:
                self._log(
                    "  ⚠ Active scan requested but active_consent=False in config.\n"
                    "    Set active_consent=True to confirm you have permission to scan.",
                    error=True,
                )
            else:
                allowed, msg = check_feature("active_scan", self.license)
                if not allowed:
                    self._log(msg, error=True)
                else:
                    self._log("  → Running active scans (Pro, consent confirmed)...")

                    self._log("     · SQL injection")
                    categories.append(injection.scan_sqli(self.target, self.client, self.config.sqli_depth))

                    self._log("     · Reflected XSS")
                    categories.append(injection.scan_xss(self.target, self.client, self.config.xss_depth))

                    self._log("     · Sensitive file discovery")
                    categories.append(discovery.scan_discovery(self.target, self.client))

                    self._log("     · SSRF")
                    categories.append(discovery.scan_ssrf(self.target, self.client))

                    self._log("     · Open redirect")
                    categories.append(redirect.scan_redirect(self.target, self.client))

                    self._log("     · Authentication (default credentials)")
                    categories.append(redirect.scan_auth(self.target, self.client))

        completed_at = datetime.utcnow()
        duration     = (completed_at - started_at).total_seconds()
        self._log(f"  ✓ Scan complete in {duration:.1f}s")

        return ScanReport(
            target=self.target,
            scan_mode=self.mode,
            started_at=started_at,
            completed_at=completed_at,
            categories=categories,
        )

    def save_report(
        self,
        report:      ScanReport,
        output_path: str,
        fmt:         str = "html",
    ) -> str:
        """Save the report to disk. fmt = 'html' | 'pdf' | 'json'"""
        from .reporters import html_reporter, pdf_reporter
        import json

        brand      = self.config.brand_name
        tagline    = self.config.brand_tagline
        author     = self.config.report_author

        if fmt == "html":
            path = html_reporter.generate(report, output_path, brand, tagline, author)
            self._log(f"  ✓ HTML report saved → {path}")
            return path

        elif fmt == "pdf":
            path = pdf_reporter.generate(report, output_path, brand, tagline, author)
            self._log(f"  ✓ PDF report saved → {path}")
            return path

        elif fmt == "json":
            from pathlib import Path
            data = {
                "target":        report.target,
                "scan_mode":     report.scan_mode.value,
                "started_at":    report.started_at.isoformat(),
                "completed_at":  report.completed_at.isoformat(),
                "overall_score": report.overall_score,
                "score_label":   report.score_label,
                "summary": {
                    "critical": report.critical_count,
                    "high":     report.high_count,
                    "medium":   report.medium_count,
                    "low":      report.low_count,
                },
                "owasp": report.owasp_coverage(),
                "categories": [
                    {
                        "name":  c.name,
                        "score": c.score,
                        "findings": [
                            {
                                "title":       f.title,
                                "description": f.description,
                                "severity":    f.severity.value,
                                "category":    f.category,
                                "remediation": f.remediation,
                                "evidence":    f.evidence,
                                "cwe":         f.cwe,
                                "owasp":       f.owasp,
                            }
                            for f in c.findings
                        ],
                    }
                    for c in report.categories
                ],
            }
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self._log(f"  ✓ JSON report saved → {output_path}")
            return output_path

        else:
            raise ValueError(f"Unknown format '{fmt}'. Use 'html', 'pdf', or 'json'.")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _log(self, msg: str, error: bool = False):
        if self.verbose or error:
            print(msg, file=sys.stderr if error else sys.stdout)
