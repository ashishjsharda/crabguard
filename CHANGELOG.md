# Changelog

All notable changes to CrabGuard are documented here.

## [1.0.1] — 2026-06-22
### Fixed
- Updated homepage and repository URLs to correct GitHub location (ashishjsharda/crabguard)
- Fixed license and changelog links in package metadata

## [1.0.0] — 2026-06-21

### 🎉 Initial Release

**Passive Scanners (free, open-source)**
- Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP
- Cookie security: HttpOnly, Secure, SameSite flags, sensitive cookie detection
- TLS/HTTPS: certificate expiry, hostname validation, HSTS preload check
- Content analysis: mixed content, Subresource Integrity, vulnerable JS libraries (jQuery, Bootstrap, Lodash, Moment, Angular)
- Form security: CSRF token detection, insecure action URLs
- Information disclosure: CORS misconfiguration, stack trace detection, server fingerprinting
- Sensitive data patterns: AWS keys, JWTs, private keys, credit cards, SSNs in page source

**Active Scanners (requires API key)**
- SQL injection: error-based + time-based blind detection
- Reflected XSS: canary-based detection across URL parameters
- Sensitive file discovery: 48 paths including .env, .git, wp-config, swagger, actuator
- SSRF: AWS/GCP metadata endpoint probing
- Open redirect: common redirect parameter detection
- Authentication: default credentials testing on admin panels

**Reports**
- Beautiful branded HTML reports with score ring, OWASP Top 10 grid, per-category findings
- PDF reports with CrabGuard watermark (requires `pip install crabguard[pdf]`)
- JSON output for CI/CD pipeline integration

**CLI**
- `crabguard scan <url>` — passive scan
- `crabguard scan <url> --mode full --consent` — full active scan
- `crabguard scan <url> --proxy http://127.0.0.1:8080` — route through Burp Suite
- Multiple output formats: `--format html|pdf|json`
