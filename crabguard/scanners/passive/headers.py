"""
CrabGuard – Passive Scanner: Security Headers
"""
from __future__ import annotations
import requests
from ...models import Finding, Severity, CategoryResult


REQUIRED_HEADERS = [
    {
        "name":        "Content-Security-Policy",
        "short":       "CSP",
        "severity":    Severity.HIGH,
        "remediation": "Add 'Content-Security-Policy' header. Start with: Content-Security-Policy: default-src 'self'",
        "cwe":         "CWE-693",
    },
    {
        "name":        "Strict-Transport-Security",
        "short":       "HSTS",
        "severity":    Severity.HIGH,
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe":         "CWE-311",
    },
    {
        "name":        "X-Frame-Options",
        "short":       "XFO",
        "severity":    Severity.MEDIUM,
        "remediation": "Add: X-Frame-Options: SAMEORIGIN  (or DENY for stricter protection)",
        "cwe":         "CWE-1021",
    },
    {
        "name":        "X-Content-Type-Options",
        "short":       "XCTO",
        "severity":    Severity.LOW,
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "cwe":         "CWE-430",
    },
    {
        "name":        "Referrer-Policy",
        "short":       "RP",
        "severity":    Severity.LOW,
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe":         "CWE-200",
    },
    {
        "name":        "Permissions-Policy",
        "short":       "PP",
        "severity":    Severity.LOW,
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "cwe":         "CWE-272",
    },
    {
        "name":        "Cross-Origin-Opener-Policy",
        "short":       "COOP",
        "severity":    Severity.LOW,
        "remediation": "Add: Cross-Origin-Opener-Policy: same-origin",
        "cwe":         "CWE-346",
    },
    {
        "name":        "Cross-Origin-Resource-Policy",
        "short":       "CORP",
        "severity":    Severity.LOW,
        "remediation": "Add: Cross-Origin-Resource-Policy: same-origin",
        "cwe":         "CWE-346",
    },
]

LEAKY_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "X-Backend-Server",
]

CSP_UNSAFE = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]


def scan(response: requests.Response) -> CategoryResult:
    headers  = {k.lower(): v for k, v in response.headers.items()}
    findings = []
    penalty  = 0

    # ── Required headers ─────────────────────────────────────────────────────
    for h in REQUIRED_HEADERS:
        name = h["name"].lower()
        if name in headers:
            findings.append(Finding(
                title=f"✓ {h['name']} is present",
                description=f"Value: {headers[name]}",
                severity=Severity.INFO,
                category="security_headers",
            ))
        else:
            findings.append(Finding(
                title=f"Missing {h['name']}",
                description=f"The {h['name']} header is not set.",
                severity=h["severity"],
                category="security_headers",
                remediation=h["remediation"],
                cwe=h["cwe"],
                references=["https://owasp.org/www-project-secure-headers/"],
            ))
            penalty += {Severity.HIGH: 15, Severity.MEDIUM: 8, Severity.LOW: 3}.get(h["severity"], 0)

    # ── CSP quality check ─────────────────────────────────────────────────────
    csp_value = headers.get("content-security-policy", "")
    if csp_value:
        for unsafe in CSP_UNSAFE:
            if unsafe in csp_value:
                findings.append(Finding(
                    title=f"CSP contains unsafe directive: {unsafe}",
                    description="Using unsafe directives in CSP defeats its purpose against XSS.",
                    severity=Severity.MEDIUM,
                    category="security_headers",
                    remediation=f"Remove '{unsafe}' from your Content-Security-Policy.",
                    cwe="CWE-693",
                    evidence=f"CSP: {csp_value[:200]}",
                ))
                penalty += 5

    # ── Information leaking headers ───────────────────────────────────────────
    for header in LEAKY_HEADERS:
        val = headers.get(header.lower())
        if val:
            findings.append(Finding(
                title=f"Information Disclosure via {header} header",
                description=f"The {header} header reveals server technology: {val}",
                severity=Severity.LOW,
                category="security_headers",
                remediation=f"Remove or obscure the '{header}' header in your server config.",
                cwe="CWE-200",
                evidence=f"{header}: {val}",
            ))
            penalty += 2

    score = max(0, 100 - penalty)
    return CategoryResult(
        name="Security Headers",
        score=score,
        findings=findings,
    )
