"""
CrabGuard – Active Scanner: Sensitive File Discovery & SSRF
"""
from __future__ import annotations
from urllib.parse import urlparse, urljoin

from ...models import Finding, Severity, CategoryResult
from ...utils.http_client import CrabGuardHTTPClient, inject_param, extract_params
from ...utils.patterns import SENSITIVE_PATHS, SSRF_PARAMS, SSRF_PAYLOADS

INTERESTING_STATUS = {200, 204, 301, 302, 401, 403}
FALSE_POSITIVE_CLUES = ["404", "not found", "page not found", "error 404"]


def scan_discovery(url: str, client: CrabGuardHTTPClient) -> CategoryResult:
    findings: list[Finding] = []
    penalty  = 0
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    discovered = []

    for path in SENSITIVE_PATHS:
        test_url = urljoin(base_url, path)
        resp     = client.get_no_redirect(test_url)
        if resp is None:
            continue

        if resp.status_code in INTERESTING_STATUS:
            # Filter false positives
            body_lower = (resp.text or "").lower()
            is_fp = any(clue in body_lower for clue in FALSE_POSITIVE_CLUES)
            if is_fp and resp.status_code == 200:
                continue

            severity = _path_severity(path, resp.status_code)
            if severity:
                discovered.append((path, resp.status_code, severity))

    if discovered:
        for path, status, severity in discovered:
            findings.append(Finding(
                title=f"Sensitive path accessible: {path} (HTTP {status})",
                description=_path_description(path),
                severity=severity,
                category="discovery",
                remediation=f"Restrict access to '{path}'. Return 404 (not 403) to avoid confirming existence.",
                cwe="CWE-538",
                evidence=f"URL: {base_url + path}\nStatus: {status}",
                url=base_url + path,
            ))
            penalty += {
                Severity.CRITICAL: 25,
                Severity.HIGH:     15,
                Severity.MEDIUM:    8,
                Severity.LOW:       3,
            }.get(severity, 0)
    else:
        findings.append(Finding(
            title="✓ No sensitive files or admin paths exposed",
            description=f"Tested {len(SENSITIVE_PATHS)} common sensitive paths.",
            severity=Severity.INFO,
            category="discovery",
        ))

    score = max(0, 100 - penalty)
    return CategoryResult(name="Sensitive File Discovery", score=score, findings=findings)


def scan_ssrf(url: str, client: CrabGuardHTTPClient) -> CategoryResult:
    findings: list[Finding] = []
    penalty  = 0
    params   = extract_params(url)

    ssrf_params_found = [p for p, _ in params if p.lower() in SSRF_PARAMS]

    if not ssrf_params_found:
        findings.append(Finding(
            title="No SSRF-candidate parameters in URL",
            description="No parameters with names like 'url', 'proxy', 'fetch', 'src' found.",
            severity=Severity.INFO,
            category="ssrf",
        ))
        return CategoryResult(name="SSRF", score=100, findings=findings)

    for param in ssrf_params_found:
        for payload in SSRF_PAYLOADS[:3]:
            test_url = inject_param(url, param, payload)
            resp     = client.get(test_url)
            if resp is None:
                continue

            # Heuristic: if internal metadata content appears, it's vulnerable
            indicators = [
                "ami-id", "instance-id", "iam/security-credentials",  # AWS
                "computeMetadata",                                       # GCP
                "root:x:",                                              # /etc/passwd
            ]
            for indicator in indicators:
                if indicator in (resp.text or ""):
                    findings.append(Finding(
                        title=f"SSRF vulnerability in parameter '{param}'",
                        description=f"Server fetched internal URL '{payload}' and returned sensitive content.",
                        severity=Severity.CRITICAL,
                        category="ssrf",
                        remediation=(
                            "Validate and whitelist URLs before fetching. "
                            "Use an allowlist of permitted domains. "
                            "Block requests to private IP ranges at network level."
                        ),
                        cwe="CWE-918",
                        evidence=f"Payload: {payload}\nIndicator found: {indicator}",
                        url=test_url,
                        references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
                    ))
                    penalty += 35
                    break

    if not findings or all(f.severity == Severity.INFO for f in findings):
        findings.append(Finding(
            title=f"✓ No obvious SSRF detected in {len(ssrf_params_found)} parameter(s)",
            description=f"Parameters tested: {', '.join(ssrf_params_found)}",
            severity=Severity.INFO,
            category="ssrf",
        ))

    score = max(0, 100 - penalty)
    return CategoryResult(name="SSRF", score=score, findings=findings)


def _path_severity(path: str, status: int) -> Severity | None:
    critical_paths = ["/.env", "/.git/config", "/wp-config.php", "/config.php",
                      "/.htpasswd", "/backup.sql", "/database.sql", "/db.sql",
                      "/actuator/env", "/phpinfo.php"]
    high_paths     = ["/.git/HEAD", "/config.yml", "/config.yaml", "/settings.py",
                      "/web.config", "/actuator", "/swagger", "/openapi.json",
                      "/graphql"]

    if status in (200, 204):
        if any(p in path for p in critical_paths):
            return Severity.CRITICAL
        if any(p in path for p in high_paths):
            return Severity.HIGH
        return Severity.MEDIUM

    if status in (401, 403):
        return Severity.LOW   # Path exists but is protected

    return None


def _path_description(path: str) -> str:
    desc_map = {
        "/.env":          "Environment file may contain database credentials, API keys, and secrets.",
        "/.git":          "Git repository exposed — full source code and history may be downloadable.",
        "/wp-config.php": "WordPress config file containing database credentials.",
        "/.htpasswd":     "Apache password file with password hashes.",
        "/phpinfo.php":   "PHP info page discloses server configuration and PHP version.",
        "/swagger":       "API documentation exposed — endpoints and auth mechanisms visible.",
        "/graphql":       "GraphQL endpoint exposed — may allow introspection revealing full schema.",
        "/actuator":      "Spring Boot Actuator endpoint — may expose environment, heap dumps, and more.",
        "/.well-known/security.txt": "Security contact file (informational, not a vulnerability).",
    }
    for key, desc in desc_map.items():
        if key in path:
            return desc
    return f"Sensitive path '{path}' returned an interesting HTTP response."
