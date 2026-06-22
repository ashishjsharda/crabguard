"""
CrabGuard – Active Scanner: SQL Injection & XSS
⚠️  Only runs when active_consent=True in config.
"""
from __future__ import annotations
import time
import urllib.parse
from urllib.parse import urlparse

from ...models import Finding, Severity, CategoryResult
from ...utils.http_client import CrabGuardHTTPClient, extract_params, inject_param
from ...utils.patterns import (
    SQLI_PAYLOADS, SQLI_ERROR_PATTERNS,
    XSS_PAYLOADS, XSS_CANARY,
)


def scan_sqli(url: str, client: CrabGuardHTTPClient, depth: int = 2) -> CategoryResult:
    findings: list[Finding] = []
    penalty  = 0
    params   = extract_params(url)

    if not params:
        findings.append(Finding(
            title="No URL parameters to test for SQLi",
            description="Add parameters to the URL to enable injection testing.",
            severity=Severity.INFO,
            category="injection",
        ))
        return CategoryResult(name="SQL Injection", score=100, findings=findings)

    vulnerable_params = []

    for param, _ in params:
        for payload in SQLI_PAYLOADS[:depth * 2]:
            test_url = inject_param(url, param, payload)
            resp     = client.get(test_url)
            if resp is None:
                continue

            for pattern in SQLI_ERROR_PATTERNS:
                if pattern.search(resp.text):
                    finding = Finding(
                        title=f"SQL Injection vulnerability in parameter '{param}'",
                        description=(
                            f"The parameter '{param}' appears to be vulnerable to SQL injection. "
                            "SQL error message detected in response."
                        ),
                        severity=Severity.CRITICAL,
                        category="injection",
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL strings."
                        ),
                        cwe="CWE-89",
                        evidence=f"Payload: {payload}\nError matched: {pattern.pattern}",
                        url=test_url,
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        ],
                    )
                    if param not in vulnerable_params:
                        vulnerable_params.append(param)
                        findings.append(finding)
                        penalty += 30
                    break

            # Time-based blind SQLi check (only for SLEEP payload)
            if "SLEEP" in payload.upper():
                start = time.time()
                resp2 = client.get(inject_param(url, param, "1' AND SLEEP(2)--"))
                elapsed = time.time() - start
                if resp2 and elapsed >= 2.0 and param not in vulnerable_params:
                    findings.append(Finding(
                        title=f"Time-based Blind SQLi in parameter '{param}'",
                        description=f"Response delayed {elapsed:.1f}s with SLEEP payload — indicates blind SQL injection.",
                        severity=Severity.CRITICAL,
                        category="injection",
                        remediation="Use parameterized queries. Sanitize all user inputs server-side.",
                        cwe="CWE-89",
                        evidence=f"Response time: {elapsed:.1f}s (expected ~0s)",
                        url=test_url,
                    ))
                    vulnerable_params.append(param)
                    penalty += 30

    if not vulnerable_params:
        findings.append(Finding(
            title=f"✓ No SQLi detected in {len(params)} parameter(s) tested",
            description=f"Parameters tested: {', '.join(p for p, _ in params)}",
            severity=Severity.INFO,
            category="injection",
        ))

    score = max(0, 100 - penalty)
    return CategoryResult(name="SQL Injection", score=score, findings=findings)


def scan_xss(url: str, client: CrabGuardHTTPClient, depth: int = 2) -> CategoryResult:
    findings: list[Finding] = []
    penalty  = 0
    params   = extract_params(url)

    if not params:
        findings.append(Finding(
            title="No URL parameters to test for XSS",
            description="Add parameters to the URL to enable XSS testing.",
            severity=Severity.INFO,
            category="xss",
        ))
        return CategoryResult(name="XSS (Reflected)", score=100, findings=findings)

    vulnerable_params = []

    for param, _ in params:
        for payload in XSS_PAYLOADS[:depth * 2]:
            test_url = inject_param(url, param, payload)
            resp     = client.get(test_url)
            if resp is None:
                continue

            if XSS_CANARY in resp.text:
                # Check if it's actually rendered (not just in a comment or attribute)
                raw = resp.text
                idx = raw.find(XSS_CANARY)
                context = raw[max(0, idx-50):idx+50] if idx >= 0 else ""

                finding = Finding(
                    title=f"Reflected XSS in parameter '{param}'",
                    description=(
                        f"The XSS canary '{XSS_CANARY}' was reflected back in the response "
                        "without proper encoding, indicating a reflected XSS vulnerability."
                    ),
                    severity=Severity.HIGH,
                    category="xss",
                    remediation=(
                        "HTML-encode all user-controlled output. "
                        "Use a strong Content-Security-Policy. "
                        "Use a templating engine with auto-escaping."
                    ),
                    cwe="CWE-79",
                    evidence=f"Payload: {payload}\nContext: ...{context}...",
                    url=test_url,
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                )
                if param not in vulnerable_params:
                    vulnerable_params.append(param)
                    findings.append(finding)
                    penalty += 20

    if not vulnerable_params:
        findings.append(Finding(
            title=f"✓ No reflected XSS detected in {len(params)} parameter(s)",
            description=f"Parameters tested: {', '.join(p for p, _ in params)}",
            severity=Severity.INFO,
            category="xss",
        ))

    score = max(0, 100 - penalty)
    return CategoryResult(name="XSS (Reflected)", score=score, findings=findings)
