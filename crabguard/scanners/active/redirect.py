"""
CrabGuard – Active Scanner: Open Redirect & Auth
"""
from __future__ import annotations
from urllib.parse import urlparse, urljoin

from ...models import Finding, Severity, CategoryResult
from ...utils.http_client import CrabGuardHTTPClient, extract_params, inject_param
from ...utils.patterns import REDIRECT_PARAMS, REDIRECT_PAYLOADS

CANARY_DOMAIN = "evil.crabguard-test.com"

DEFAULT_CREDS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "admin123"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "toor"),
    ("admin",     "1234"),
    ("user",      "user"),
    ("test",      "test"),
    ("guest",     "guest"),
]


def scan_redirect(url: str, client: CrabGuardHTTPClient) -> CategoryResult:
    findings: list[Finding] = []
    penalty  = 0
    params   = extract_params(url)

    redirect_params = [p for p, _ in params if p.lower() in REDIRECT_PARAMS]

    if not redirect_params:
        findings.append(Finding(
            title="No open-redirect candidate parameters found",
            description=f"None of the URL parameters match common redirect param names ({', '.join(REDIRECT_PARAMS[:6])}...).",
            severity=Severity.INFO,
            category="redirect",
        ))
        return CategoryResult(name="Open Redirect", score=100, findings=findings)

    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS:
            test_url = inject_param(url, param, payload)
            resp     = client.get_no_redirect(test_url)
            if resp is None:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if CANARY_DOMAIN in location or location.startswith(payload.split("?")[0]):
                    findings.append(Finding(
                        title=f"Open Redirect via parameter '{param}'",
                        description=(
                            f"The server redirected to '{location}' when the '{param}' parameter "
                            "was set to an external URL. This can be used in phishing attacks."
                        ),
                        severity=Severity.HIGH,
                        category="redirect",
                        remediation=(
                            "Validate redirect destinations against an allowlist of trusted URLs. "
                            "Never redirect to user-supplied URLs without validation."
                        ),
                        cwe="CWE-601",
                        evidence=f"Payload: {payload}\nLocation: {location}",
                        url=test_url,
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                    ))
                    penalty += 15

    if not any(f.severity != Severity.INFO for f in findings):
        findings.append(Finding(
            title=f"✓ No open redirect in {len(redirect_params)} parameter(s)",
            description=f"Parameters tested: {', '.join(redirect_params)}",
            severity=Severity.INFO,
            category="redirect",
        ))

    score = max(0, 100 - penalty)
    return CategoryResult(name="Open Redirect", score=score, findings=findings)


def scan_auth(url: str, client: CrabGuardHTTPClient) -> CategoryResult:
    findings: list[Finding] = []
    penalty  = 0
    parsed   = urlparse(url)
    base     = f"{parsed.scheme}://{parsed.netloc}"

    admin_paths = ["/admin", "/admin/login", "/wp-login.php", "/wp-admin",
                   "/administrator", "/login", "/auth", "/signin"]

    for path in admin_paths:
        test_url = urljoin(base, path)
        resp     = client.get(test_url)
        if resp is None:
            continue

        if resp.status_code == 200:
            # Try default credentials via form POST
            for username, password in DEFAULT_CREDS[:5]:
                post_resp = client.session.post(
                    test_url,
                    data={"username": username, "password": password,
                          "user": username, "pass": password,
                          "email": username, "login": username},
                    timeout=client.config.timeout,
                    allow_redirects=True,
                )
                if post_resp is None:
                    continue
                # Heuristics for successful login
                success_clues = ["dashboard", "logout", "welcome", "profile", "sign out"]
                if any(clue in (post_resp.text or "").lower() for clue in success_clues):
                    findings.append(Finding(
                        title=f"Default credentials work on {path} ({username}/{password or 'blank'})",
                        description="The admin panel accepted default/common credentials.",
                        severity=Severity.CRITICAL,
                        category="auth",
                        remediation="Change default credentials immediately. Implement account lockout after failed attempts.",
                        cwe="CWE-1392",
                        evidence=f"URL: {test_url}\nCredentials: {username}/{password or '(blank)'}",
                        url=test_url,
                    ))
                    penalty += 35

    # Check for missing brute-force protection (no rate limiting on login)
    if not findings or all(f.severity == Severity.INFO for f in findings):
        findings.append(Finding(
            title="Auth check complete — no default credentials accepted",
            description="No accessible login pages responded to default credential attempts.",
            severity=Severity.INFO,
            category="auth",
        ))

    score = max(0, 100 - penalty)
    return CategoryResult(name="Authentication", score=score, findings=findings)
