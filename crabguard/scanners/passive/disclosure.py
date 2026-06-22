"""
CrabGuard – Passive Scanner: Information Disclosure
(CORS, network requests, server fingerprinting)
"""
from __future__ import annotations
import re
import requests
from ...models import Finding, Severity, CategoryResult


CORS_DANGEROUS = ["*", "null"]

TECH_HEADERS = {
    "server":              "Web Server",
    "x-powered-by":        "Backend Technology",
    "x-aspnet-version":    "ASP.NET Version",
    "x-aspnetmvc-version": "ASP.NET MVC Version",
    "x-generator":         "CMS/Framework",
    "x-drupal-cache":      "Drupal CMS",
    "x-wordpress-theme":   "WordPress Theme",
    "x-backend-server":    "Backend Server",
    "x-varnish":           "Varnish Cache",
    "cf-ray":              "Cloudflare CDN",
    "x-amz-request-id":    "AWS",
    "x-goog-resource-type":"Google Cloud",
}

ERROR_PATTERNS = [
    re.compile(r, re.I) for r in [
        r"stack trace",
        r"at [A-Za-z0-9_$.]+\([A-Za-z0-9_.]+:\d+",
        r"Traceback \(most recent call last\)",
        r"Exception in thread",
        r"SyntaxError:",
        r"TypeError:",
        r"ReferenceError:",
        r"NullPointerException",
        r"undefined index",
        r"SQLSTATE\[",
        r"Warning: include\(",
        r"Fatal error:",
        r"Parse error:",
    ]
]


def scan(response: requests.Response) -> CategoryResult:
    findings: list[Finding] = []
    penalty  = 0
    headers  = {k.lower(): v for k, v in response.headers.items()}

    # ── CORS ─────────────────────────────────────────────────────────────────
    acao = headers.get("access-control-allow-origin", "")
    if acao:
        if acao in CORS_DANGEROUS:
            findings.append(Finding(
                title=f"CORS: Access-Control-Allow-Origin: {acao}",
                description="A wildcard CORS policy allows any origin to read responses from this server, which can expose sensitive API data.",
                severity=Severity.HIGH,
                category="disclosure",
                remediation="Set Access-Control-Allow-Origin to specific trusted origins, never '*' for authenticated endpoints.",
                cwe="CWE-346",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
            ))
            penalty += 15
        else:
            findings.append(Finding(
                title=f"✓ CORS restricted to: {acao}",
                description="",
                severity=Severity.INFO,
                category="disclosure",
            ))
    else:
        findings.append(Finding(
            title="No CORS headers set",
            description="If this is an API, CORS configuration should be explicitly set.",
            severity=Severity.INFO,
            category="disclosure",
        ))

    acac = headers.get("access-control-allow-credentials", "")
    if acac == "true" and acao in CORS_DANGEROUS:
        findings.append(Finding(
            title="CORS: Credentials allowed with wildcard origin",
            description="Combining Access-Control-Allow-Credentials: true with a wildcard origin is a critical misconfiguration.",
            severity=Severity.CRITICAL,
            category="disclosure",
            remediation="Never use wildcard origin when allowing credentials. Explicitly whitelist trusted origins.",
            cwe="CWE-346",
        ))
        penalty += 25

    # ── Technology fingerprinting ─────────────────────────────────────────────
    disclosed = []
    for header, label in TECH_HEADERS.items():
        val = headers.get(header)
        if val:
            disclosed.append(f"{label}: {val}")

    if disclosed:
        findings.append(Finding(
            title=f"Technology stack disclosed in {len(disclosed)} header(s)",
            description="Server headers reveal technology details that help attackers fingerprint and target known CVEs.",
            severity=Severity.LOW,
            category="disclosure",
            remediation="Remove or genericize Server, X-Powered-By, and version headers in your server config.",
            cwe="CWE-200",
            evidence="\n".join(disclosed),
        ))
        penalty += len(disclosed) * 2

    # ── Error pages / stack traces ────────────────────────────────────────────
    body = response.text or ""
    for pattern in ERROR_PATTERNS:
        if pattern.search(body):
            findings.append(Finding(
                title="Stack trace / error details visible in response",
                description="Detailed error messages reveal internal paths, framework versions, and code structure to attackers.",
                severity=Severity.HIGH,
                category="disclosure",
                remediation="Disable detailed error reporting in production. Return generic error pages.",
                cwe="CWE-209",
                evidence="Pattern matched: " + pattern.pattern,
            ))
            penalty += 12
            break   # One finding is enough

    # ── Security.txt ─────────────────────────────────────────────────────────
    # (informational – noted but not penalized)
    findings.append(Finding(
        title="Consider adding /.well-known/security.txt",
        description="security.txt helps security researchers report vulnerabilities to you responsibly.",
        severity=Severity.INFO,
        category="disclosure",
        remediation="Create /.well-known/security.txt per RFC 9116. Use https://securitytxt.org/ to generate one.",
        references=["https://securitytxt.org/"],
    ))

    score = max(0, 100 - penalty)
    return CategoryResult(name="Information Disclosure", score=score, findings=findings)
