# 🦀 CrabGuard

**Enterprise web security scanner. Burp Suite + OWASP ZAP — without the $400/year license.**

[![PyPI version](https://badge.fury.io/py/crabguard.svg)](https://badge.fury.io/py/crabguard)
[![Python](https://img.shields.io/pypi/pyversions/crabguard)](https://pypi.org/project/crabguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-ashishjsharda%2Fcrabguard-181717?logo=github)](https://github.com/ashishjsharda/crabguard)

```bash
pip install crabguard
crabguard scan https://your-site.com
```

> Scans for OWASP Top 10 vulnerabilities and generates a beautiful, branded security report in seconds.

---

## What it checks

| Category | Free (Passive) | Pro (Active) |
|---|:---:|:---:|
| Security Headers (CSP, HSTS, XFO...) | ✅ | ✅ |
| Cookie Security (HttpOnly, Secure, SameSite) | ✅ | ✅ |
| TLS/HTTPS + Certificate Expiry | ✅ | ✅ |
| Mixed Content | ✅ | ✅ |
| Subresource Integrity (SRI) | ✅ | ✅ |
| Vulnerable JS Libraries | ✅ | ✅ |
| CORS Misconfiguration | ✅ | ✅ |
| Information Disclosure | ✅ | ✅ |
| SQL Injection (error + time-based blind) | — | ✅ |
| Reflected XSS | — | ✅ |
| Sensitive File Discovery (.env, .git, ...) | — | ✅ |
| SSRF | — | ✅ |
| Open Redirect | — | ✅ |
| Default Credentials | — | ✅ |
| **PDF Reports** | — | ✅ |
| **White-label Reports** | — | ✅ |

---

## Quick Start

```bash
# Install
pip install crabguard

# Passive scan (free, no account needed)
crabguard scan https://example.com

# Full active scan (Pro — requires API key)
crabguard scan https://example.com --mode full --api-key YOUR_KEY --consent

# Save as PDF
crabguard scan https://example.com --format pdf --api-key YOUR_KEY

# Route through Burp Suite / OWASP ZAP
crabguard scan https://example.com --proxy http://127.0.0.1:8080

# JSON output for CI/CD
crabguard scan https://example.com --format json --quiet
echo $?  # exit 1 if critical/high findings, 0 if clean
```

---

## Python API

```python
from crabguard import CrabGuardScanner, CrabGuardConfig, ScanMode

# Free passive scan
scanner = CrabGuardScanner("https://example.com", verbose=True)
report  = scanner.scan()
scanner.save_report(report, "report.html")

# Pro active scan
config  = CrabGuardConfig(api_key="YOUR_KEY", active_consent=True)
scanner = CrabGuardScanner("https://example.com", mode=ScanMode.FULL, config=config)
report  = scanner.scan()
scanner.save_report(report, "report.html")
scanner.save_report(report, "report.pdf", fmt="pdf")

# Access findings programmatically
for finding in report.all_findings:
    print(f"[{finding.severity.value.upper()}] {finding.title}")
    if finding.remediation:
        print(f"  Fix: {finding.remediation}")
```

---

## CI/CD Integration (GitHub Actions)

```yaml
- name: Security scan
  run: |
    pip install crabguard
    crabguard scan ${{ env.STAGING_URL }} --format json --quiet
  # Fails the build automatically if critical/high findings are found
```

---

## Report Sample

CrabGuard generates a full HTML or PDF report with:
- Overall security score (0–100)
- Per-category scores and OWASP Top 10 mapping
- Detailed findings with remediation steps and code snippets
- CrabGuard branded watermark (white-label available on Pro)

---

## Pricing

| | Free | Pro | Enterprise |
|---|:---:|:---:|:---:|
| Passive scan | ✅ | ✅ | ✅ |
| Active scan (SQLi, XSS, SSRF...) | — | ✅ | ✅ |
| PDF reports + white-label | — | ✅ | ✅ |
| Scan history & dashboard | — | — | ✅ |
| Team seats | — | — | ✅ |
| SLA + priority support | — | — | ✅ |
| Price | Free | $49/mo | Contact us |

Get your API key at **[ashishjsharda.github.io/crabguard](https://ashishjsharda.github.io/crabguard)**

---

## ⚠️ Responsible Use

Active scanning sends real payloads to the target server. **Only scan systems you own or have explicit written permission to test.** Unauthorized scanning may be illegal under the CFAA and similar laws. Always pass `--consent` to confirm you have permission.

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).

Built with ❤️ by [CrabGuard Security](https://ashishjsharda.github.io/crabguard)
