"""
CrabGuard – Passive Scanner: Cookie Security
"""
from __future__ import annotations
import re
import requests
from ...models import Finding, Severity, CategoryResult

SENSITIVE_COOKIE_PATTERNS = re.compile(
    r"(session|auth|token|jwt|login|user|account|access|refresh|csrf|sid|ssid|bearer)",
    re.I,
)

COOKIE_REMEDIATION = (
    "Set cookies with security flags:\n"
    "  Set-Cookie: name=value; HttpOnly; Secure; SameSite=Strict; Path=/"
)


def scan(response: requests.Response) -> CategoryResult:
    findings = []
    penalty  = 0

    # Collect all Set-Cookie headers
    raw_cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not raw_cookies:
        # Fallback: parse from response.cookies
        raw_cookies = []
        for c in response.cookies:
            flags = []
            if c.has_nonstandard_attr("HttpOnly"): flags.append("HttpOnly")
            if c.secure: flags.append("Secure")
            if c.has_nonstandard_attr("SameSite"): flags.append(f"SameSite={c._rest.get('SameSite', '')}")
            raw_cookies.append(f"{c.name}={c.value}; " + "; ".join(flags))

    parsed = _parse_cookies(response)

    if not parsed:
        findings.append(Finding(
            title="No cookies set by this response",
            description="No Set-Cookie headers found.",
            severity=Severity.INFO,
            category="cookies",
        ))
        return CategoryResult(name="Cookie Security", score=100, findings=findings)

    findings.append(Finding(
        title=f"Found {len(parsed)} cookie(s)",
        description=", ".join(c["name"] for c in parsed),
        severity=Severity.INFO,
        category="cookies",
    ))

    missing_httponly = [c for c in parsed if not c["httponly"]]
    missing_secure   = [c for c in parsed if not c["secure"]]
    missing_samesite = [c for c in parsed if not c["samesite"]]
    sensitive_js     = [c for c in missing_httponly if SENSITIVE_COOKIE_PATTERNS.search(c["name"])]

    if missing_httponly:
        findings.append(Finding(
            title=f"{len(missing_httponly)} cookie(s) missing HttpOnly flag",
            description="Cookies without HttpOnly are accessible to JavaScript, enabling XSS-based session theft.",
            severity=Severity.MEDIUM,
            category="cookies",
            remediation=COOKIE_REMEDIATION,
            cwe="CWE-1004",
            evidence="Affected: " + ", ".join(c["name"] for c in missing_httponly),
        ))
        penalty += 10

    if sensitive_js:
        for c in sensitive_js:
            findings.append(Finding(
                title=f"Sensitive cookie '{c['name']}' is JS-accessible (no HttpOnly)",
                description="This cookie name suggests it holds session/auth data and is readable by any script on the page.",
                severity=Severity.HIGH,
                category="cookies",
                remediation=COOKIE_REMEDIATION,
                cwe="CWE-1004",
                evidence=f"Cookie: {c['name']}",
            ))
            penalty += 15

    if missing_secure:
        findings.append(Finding(
            title=f"{len(missing_secure)} cookie(s) missing Secure flag",
            description="Cookies without Secure can be sent over HTTP, exposing them to MITM attacks.",
            severity=Severity.MEDIUM,
            category="cookies",
            remediation=COOKIE_REMEDIATION,
            cwe="CWE-614",
            evidence="Affected: " + ", ".join(c["name"] for c in missing_secure),
        ))
        penalty += 8

    if missing_samesite:
        findings.append(Finding(
            title=f"{len(missing_samesite)} cookie(s) missing SameSite attribute",
            description="Cookies without SameSite are sent with cross-site requests, enabling CSRF attacks.",
            severity=Severity.LOW,
            category="cookies",
            remediation="Add SameSite=Strict or SameSite=Lax to all cookies.",
            cwe="CWE-352",
            evidence="Affected: " + ", ".join(c["name"] for c in missing_samesite),
        ))
        penalty += 5

    score = max(0, 100 - penalty)
    return CategoryResult(name="Cookie Security", score=score, findings=findings)


def _parse_cookies(response: requests.Response) -> list[dict]:
    parsed = []
    for cookie in response.cookies:
        parsed.append({
            "name":     cookie.name,
            "httponly": cookie.has_nonstandard_attr("HttpOnly"),
            "secure":   cookie.secure,
            "samesite": bool(cookie._rest.get("SameSite")),
        })
    # Also try parsing raw headers for more accuracy
    raw = response.headers.get("Set-Cookie", "")
    if raw and not parsed:
        parts = raw.split(";")
        name  = parts[0].split("=")[0].strip() if parts else "unknown"
        flags = [p.strip().lower() for p in parts[1:]]
        parsed.append({
            "name":     name,
            "httponly": "httponly" in flags,
            "secure":   "secure" in flags,
            "samesite": any(f.startswith("samesite") for f in flags),
        })
    return parsed
