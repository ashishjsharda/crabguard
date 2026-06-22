"""
CrabGuard – Passive Scanner: TLS / HTTPS
"""
from __future__ import annotations
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import requests
from ...models import Finding, Severity, CategoryResult


def scan(url: str, response: requests.Response) -> CategoryResult:
    findings = []
    penalty  = 0
    parsed   = urlparse(url)
    hostname = parsed.hostname

    # ── HTTPS check ───────────────────────────────────────────────────────────
    if parsed.scheme == "https":
        findings.append(Finding(
            title="✓ Site served over HTTPS",
            description="All traffic is encrypted in transit.",
            severity=Severity.INFO,
            category="tls",
        ))
    else:
        findings.append(Finding(
            title="Site served over HTTP (not HTTPS)",
            description="All data between the browser and server is transmitted in plaintext.",
            severity=Severity.CRITICAL,
            category="tls",
            remediation="Obtain an SSL/TLS certificate (free via Let's Encrypt) and redirect all HTTP to HTTPS.",
            cwe="CWE-319",
        ))
        penalty += 40
        return CategoryResult(name="TLS / HTTPS", score=max(0, 100-penalty), findings=findings)

    # ── HSTS check ────────────────────────────────────────────────────────────
    hsts = response.headers.get("Strict-Transport-Security", "")
    if hsts:
        findings.append(Finding(
            title="✓ HSTS header present",
            description=f"Value: {hsts}",
            severity=Severity.INFO,
            category="tls",
        ))
        if "preload" not in hsts:
            findings.append(Finding(
                title="HSTS missing 'preload' directive",
                description="Without preload, browsers may still make the first request over HTTP.",
                severity=Severity.LOW,
                category="tls",
                remediation="Add 'preload' to your HSTS header and submit to https://hstspreload.org/",
                cwe="CWE-311",
            ))
            penalty += 3
        if "includeSubDomains" not in hsts:
            findings.append(Finding(
                title="HSTS missing 'includeSubDomains'",
                description="Subdomains are not covered by HSTS and may be accessed over HTTP.",
                severity=Severity.LOW,
                category="tls",
                remediation="Add 'includeSubDomains' to your HSTS header.",
                cwe="CWE-311",
            ))
            penalty += 3
        max_age = _extract_max_age(hsts)
        if max_age and max_age < 15552000:
            findings.append(Finding(
                title=f"HSTS max-age too short ({max_age}s)",
                description="HSTS max-age should be at least 180 days (15552000 seconds).",
                severity=Severity.LOW,
                category="tls",
                remediation="Set max-age=31536000 (1 year).",
                cwe="CWE-311",
            ))
            penalty += 3

    # ── Certificate check ─────────────────────────────────────────────────────
    cert_info = _get_cert_info(hostname, parsed.port or 443)
    if cert_info:
        days_left = cert_info.get("days_left", 999)
        expiry    = cert_info.get("expiry", "unknown")

        if days_left < 0:
            findings.append(Finding(
                title="SSL Certificate EXPIRED",
                description=f"Certificate expired on {expiry}.",
                severity=Severity.CRITICAL,
                category="tls",
                remediation="Renew your SSL certificate immediately.",
                cwe="CWE-298",
            ))
            penalty += 30
        elif days_left < 14:
            findings.append(Finding(
                title=f"SSL Certificate expiring SOON ({days_left} days)",
                description=f"Certificate expires {expiry}.",
                severity=Severity.HIGH,
                category="tls",
                remediation="Renew your SSL certificate before it expires.",
                cwe="CWE-298",
            ))
            penalty += 15
        elif days_left < 30:
            findings.append(Finding(
                title=f"SSL Certificate expiring in {days_left} days",
                description=f"Certificate expires {expiry}.",
                severity=Severity.MEDIUM,
                category="tls",
                remediation="Renew your SSL certificate soon.",
                cwe="CWE-298",
            ))
            penalty += 5
        else:
            findings.append(Finding(
                title=f"✓ SSL Certificate valid ({days_left} days remaining)",
                description=f"Expires: {expiry}",
                severity=Severity.INFO,
                category="tls",
            ))

        subject = cert_info.get("subject", {})
        cn      = subject.get("commonName", "")
        if hostname and cn:
            if not _cert_matches_host(cn, hostname):
                findings.append(Finding(
                    title="SSL Certificate hostname mismatch",
                    description=f"Certificate CN '{cn}' does not match host '{hostname}'.",
                    severity=Severity.CRITICAL,
                    category="tls",
                    remediation="Obtain a certificate that covers this hostname.",
                    cwe="CWE-297",
                ))
                penalty += 25
            else:
                findings.append(Finding(
                    title=f"✓ Certificate matches hostname ({cn})",
                    description="",
                    severity=Severity.INFO,
                    category="tls",
                ))

    score = max(0, 100 - penalty)
    return CategoryResult(name="TLS / HTTPS", score=score, findings=findings)


def _extract_max_age(hsts: str) -> int | None:
    for part in hsts.split(";"):
        p = part.strip()
        if p.lower().startswith("max-age="):
            try:
                return int(p.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _get_cert_info(hostname: str, port: int = 443) -> dict | None:
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.create_connection((hostname, port), timeout=5),
                               server_hostname=hostname)
        cert = conn.getpeercert()
        conn.close()
        not_after = cert.get("notAfter", "")
        expiry    = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
        days_left = (expiry - datetime.utcnow()).days if expiry else 999
        subject   = dict(x[0] for x in cert.get("subject", []))
        return {"days_left": days_left, "expiry": str(expiry), "subject": subject}
    except Exception:
        return None


def _cert_matches_host(cn: str, hostname: str) -> bool:
    if cn.startswith("*."):
        parts_cn   = cn[2:].lower().split(".")
        parts_host = hostname.lower().split(".")
        return parts_host[1:] == parts_cn
    return cn.lower() == hostname.lower()
