"""
CrabGuard – Passive Scanner: Content Analysis
(SRI, mixed content, forms, vulnerable JS libraries, CSP quality)
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from ...models import Finding, Severity, CategoryResult
from ...utils.patterns import VULN_JS_LIBS, SENSITIVE_PATTERNS


def scan(url: str, response: requests.Response) -> CategoryResult:
    findings: list[Finding] = []
    penalty  = 0

    ct = response.headers.get("Content-Type", "")
    if "html" not in ct:
        findings.append(Finding(
            title="Response is not HTML – content checks skipped",
            description=f"Content-Type: {ct}",
            severity=Severity.INFO,
            category="content",
        ))
        return CategoryResult(name="Content Analysis", score=100, findings=findings)

    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        findings.append(Finding(
            title="Could not parse HTML",
            description=str(e),
            severity=Severity.INFO,
            category="content",
        ))
        return CategoryResult(name="Content Analysis", score=90, findings=findings)

    parsed_base = urlparse(url)

    # ── Mixed content ─────────────────────────────────────────────────────────
    if parsed_base.scheme == "https":
        http_resources = []
        for tag in soup.find_all(["script", "link", "img", "iframe", "audio", "video", "source"]):
            src = tag.get("src") or tag.get("href") or ""
            if src.startswith("http://"):
                http_resources.append(src)

        if http_resources:
            findings.append(Finding(
                title=f"Mixed Content: {len(http_resources)} HTTP resource(s) on HTTPS page",
                description="HTTP resources on HTTPS pages can be intercepted and modified by MITM attackers.",
                severity=Severity.HIGH,
                category="content",
                remediation="Change all resource URLs to HTTPS or use protocol-relative URLs (//example.com/...).",
                cwe="CWE-319",
                evidence="\n".join(http_resources[:5]),
            ))
            penalty += 15
        else:
            findings.append(Finding(
                title="✓ No mixed content detected",
                description="All resources are loaded over HTTPS.",
                severity=Severity.INFO,
                category="content",
            ))

    # ── Subresource Integrity (SRI) ───────────────────────────────────────────
    ext_scripts = [s for s in soup.find_all("script", src=True)
                   if _is_external(s["src"], parsed_base)]
    ext_styles  = [l for l in soup.find_all("link", rel=True, href=True)
                   if "stylesheet" in l.get("rel", []) and _is_external(l["href"], parsed_base)]

    no_sri_scripts = [s["src"] for s in ext_scripts if not s.get("integrity")]
    no_sri_styles  = [l["href"] for l in ext_styles  if not l.get("integrity")]

    if no_sri_scripts:
        findings.append(Finding(
            title=f"{len(no_sri_scripts)} external script(s) without SRI integrity attribute",
            description="If a CDN is compromised, these scripts can serve malicious code to your users.",
            severity=Severity.MEDIUM,
            category="content",
            remediation='Add integrity="sha384-HASH" crossorigin="anonymous" to each external <script>.',
            cwe="CWE-829",
            evidence="\n".join(no_sri_scripts[:5]),
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
        ))
        penalty += 8
    else:
        findings.append(Finding(
            title="✓ All external scripts have SRI hashes",
            description="",
            severity=Severity.INFO,
            category="content",
        ))

    if no_sri_styles:
        findings.append(Finding(
            title=f"{len(no_sri_styles)} external stylesheet(s) without SRI",
            description="External stylesheets without SRI can be tampered with.",
            severity=Severity.LOW,
            category="content",
            remediation='Add integrity="sha384-HASH" crossorigin="anonymous" to each external <link>.',
            cwe="CWE-829",
            evidence="\n".join(no_sri_styles[:3]),
        ))
        penalty += 3

    # ── Vulnerable JS libraries ───────────────────────────────────────────────
    all_scripts = [s.get("src", "") for s in soup.find_all("script", src=True)]
    for lib_name, lib_info in VULN_JS_LIBS.items():
        for src in all_scripts:
            m = lib_info["pattern"].search(src)
            if m:
                ver_str = m.group(1)
                try:
                    ver = tuple(int(x) for x in ver_str.split(".")[:3])
                    vuln = lib_info["vuln_below"]
                    if ver < vuln:
                        findings.append(Finding(
                            title=f"Vulnerable {lib_name.title()} version {ver_str} detected",
                            description=lib_info["description"],
                            severity=Severity.HIGH,
                            category="content",
                            remediation=f"Upgrade {lib_name} to the latest stable version.",
                            cwe="CWE-1104",
                            evidence=f"Source: {src}",
                            references=[f"https://nvd.nist.gov/vuln/detail/{lib_info['cve']}"],
                        ))
                        penalty += 12
                except ValueError:
                    pass

    # ── Form security ─────────────────────────────────────────────────────────
    forms = soup.find_all("form")
    if forms:
        findings.append(Finding(
            title=f"Found {len(forms)} form(s)",
            description="",
            severity=Severity.INFO,
            category="content",
        ))
        insecure_forms    = []
        missing_csrf      = []
        password_autocomplete = []

        csrf_patterns = re.compile(r"(csrf|_token|authenticity_token|xsrf)", re.I)

        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").lower()

            if action.startswith("http://"):
                insecure_forms.append(action)

            has_csrf = bool(form.find("input", attrs={"name": csrf_patterns}))
            has_password = bool(form.find("input", attrs={"type": "password"}))

            if has_password and not has_csrf and method == "post":
                missing_csrf.append(action or "(no action)")

            for pw_input in form.find_all("input", attrs={"type": "password"}):
                if pw_input.get("autocomplete", "").lower() not in ("off", "new-password", "current-password"):
                    password_autocomplete.append(pw_input.get("name", "unnamed"))

        if insecure_forms:
            findings.append(Finding(
                title=f"{len(insecure_forms)} form(s) submit to HTTP endpoint",
                description="Form data submitted over HTTP can be intercepted.",
                severity=Severity.HIGH,
                category="content",
                remediation="Change form action URLs to HTTPS.",
                cwe="CWE-319",
                evidence="\n".join(insecure_forms),
            ))
            penalty += 15

        if missing_csrf:
            findings.append(Finding(
                title=f"{len(missing_csrf)} password form(s) may be missing CSRF token",
                description="POST forms with passwords but no visible CSRF token are vulnerable to Cross-Site Request Forgery.",
                severity=Severity.HIGH,
                category="content",
                remediation="Add a hidden CSRF token to all state-changing forms.",
                cwe="CWE-352",
                evidence="Forms: " + ", ".join(missing_csrf),
            ))
            penalty += 12

        if not insecure_forms and not missing_csrf:
            findings.append(Finding(
                title="✓ Forms appear to have good security practices",
                description="No obvious insecure form actions or missing CSRF tokens detected.",
                severity=Severity.INFO,
                category="content",
            ))

    # ── Inline event handlers (XSS risk indicator) ────────────────────────────
    inline_handlers = soup.find_all(attrs={
        k: True for k in ["onclick", "onload", "onerror", "onmouseover",
                           "onfocus", "onblur", "onsubmit", "onkeyup"]
    })
    if inline_handlers:
        findings.append(Finding(
            title=f"{len(inline_handlers)} inline event handler(s) detected",
            description="Inline handlers are XSS vectors when combined with weak CSP. Move event listeners to external JS.",
            severity=Severity.LOW,
            category="content",
            remediation="Replace onclick=... with addEventListener() in external scripts, and tighten your CSP.",
            cwe="CWE-80",
        ))
        penalty += 4

    # ── Sensitive data in page source ─────────────────────────────────────────
    page_text = response.text
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        matches = pattern.findall(page_text)
        if matches:
            findings.append(Finding(
                title=f"{pattern_name} pattern found in page source ({len(matches)} occurrence(s))",
                description="Sensitive data exposed in client-side code is visible to anyone who views the page source.",
                severity=Severity.CRITICAL if "Key" in pattern_name or "Token" in pattern_name else Severity.HIGH,
                category="content",
                remediation="Move sensitive data to server-side. Never expose credentials, keys, or PII in HTML/JS.",
                cwe="CWE-312",
                evidence=f"First match: {str(matches[0])[:80]}...",
            ))
            penalty += 20

    score = max(0, 100 - penalty)
    return CategoryResult(name="Content Analysis", score=score, findings=findings)


def _is_external(src: str, base: any) -> bool:
    if not src:
        return False
    if src.startswith("//"):
        return True
    parsed = urlparse(src)
    if not parsed.netloc:
        return False
    return parsed.netloc != base.netloc
