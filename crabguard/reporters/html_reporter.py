"""
CrabGuard – HTML Report Generator
Generates a beautiful, branded single-file HTML security report.
"""
from __future__ import annotations
import html
from datetime import datetime
from pathlib import Path

from ..models import ScanReport, Finding, Severity, CategoryResult


SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}

OWASP_COLORS = {
    "PASS": ("#10b981", "#d1fae5"),
    "WARN": ("#f59e0b", "#fef3c7"),
    "FAIL": ("#ef4444", "#fee2e2"),
    "N/A":  ("#94a3b8", "#f1f5f9"),
}


def generate(report: ScanReport, output_path: str, brand_name: str = "CrabGuard",
             brand_tagline: str = "Enterprise Web Security Scanner",
             report_author: str = "") -> str:
    """Generate an HTML report and write it to output_path. Returns the path."""

    score        = report.overall_score
    score_color  = report.score_color
    score_label  = report.score_label
    scan_ts      = report.started_at.strftime("%B %d, %Y at %I:%M %p")
    gen_ts       = report.completed_at.strftime("%B %d, %Y at %I:%M %p")
    owasp        = report.owasp_coverage()

    categories_html  = "\n".join(_render_category(c) for c in report.categories)
    owasp_html       = "\n".join(_render_owasp_row(k, v) for k, v in owasp.items())
    category_scores  = "\n".join(_render_score_card(c) for c in report.categories)

    author_line = f"<br><strong>Report prepared for:</strong> {html.escape(report_author)}" if report_author else ""

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{html.escape(brand_name)} Security Report — {html.escape(report.target)}</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box;}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f4f8;color:#1e293b;line-height:1.6;padding:32px 16px;}}
    .container{{max-width:960px;margin:0 auto;background:#fff;border-radius:20px;box-shadow:0 8px 40px rgba(0,0,0,.12);overflow:hidden;}}
    @media print{{body{{background:#fff;padding:0;}}.container{{box-shadow:none;border-radius:0;}}.no-print{{display:none;}}}}
    details summary{{list-style:none;cursor:pointer;}} details summary::-webkit-details-marker{{display:none;}}
    .badge{{display:inline-block;font-size:11px;font-weight:700;padding:3px 12px;border-radius:20px;text-transform:uppercase;letter-spacing:.5px;}}
    .badge-pass{{color:#059669;background:#d1fae5;}} .badge-warn{{color:#d97706;background:#fef3c7;}}
    .badge-fail{{color:#dc2626;background:#fee2e2;}} .badge-info{{color:#2563eb;background:#dbeafe;}}
    .badge-na{{color:#64748b;background:#f1f5f9;}}
    .finding{{background:#fff;padding:14px 16px;border-radius:10px;margin-bottom:10px;border-left:4px solid #e2e8f0;box-shadow:0 1px 3px rgba(0,0,0,.04);}}
    .finding-critical{{border-left-color:#dc2626;}} .finding-high{{border-left-color:#ef4444;}}
    .finding-medium{{border-left-color:#f59e0b;}} .finding-low{{border-left-color:#3b82f6;}}
    .finding-info{{border-left-color:#94a3b8;}}
    .finding-title{{font-weight:600;color:#1e293b;margin-bottom:4px;font-size:14px;}}
    .finding-desc{{font-size:13px;color:#64748b;margin-bottom:6px;}}
    .finding-evidence{{background:#f8fafc;border-radius:6px;padding:8px 10px;font-size:11px;color:#475569;font-family:monospace;margin-top:6px;white-space:pre-wrap;word-break:break-all;}}
    .remediation{{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:8px 10px;font-size:12px;color:#166534;margin-top:6px;}}
    .score-ring{{width:140px;height:140px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;margin:0 auto 20px;box-shadow:0 12px 35px rgba(0,0,0,.15);}}
    .score-num{{font-size:52px;font-weight:800;line-height:1;}} .score-den{{font-size:13px;opacity:.8;}}
    .cat-card{{background:#f8fafc;border-radius:10px;padding:14px;text-align:center;border:2px solid transparent;}}
    .stat-pill{{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;margin:0 2px;}}
    .watermark{{position:fixed;bottom:20px;right:20px;opacity:.06;font-size:80px;font-weight:900;color:#1e40af;transform:rotate(-15deg);pointer-events:none;z-index:0;user-select:none;}}
    .brand-badge{{display:inline-flex;align-items:center;gap:6px;background:linear-gradient(135deg,#1e40af,#7c3aed);color:#fff;padding:6px 14px;border-radius:20px;font-size:12px;font-weight:700;}}
  </style>
</head>
<body>
<div class="container">

  <!-- ── Header ─────────────────────────────────────────── -->
  <div style="background:linear-gradient(135deg,#1e40af 0%,#4f46e5 50%,#7c3aed 100%);color:#fff;padding:40px;text-align:center;position:relative;overflow:hidden;">
    <div style="position:absolute;top:-60px;right:-60px;width:200px;height:200px;background:rgba(255,255,255,.04);border-radius:50%;"></div>
    <div style="position:absolute;bottom:-80px;left:-40px;width:250px;height:250px;background:rgba(255,255,255,.03);border-radius:50%;"></div>
    <div style="position:relative;">
      <div style="display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:6px;">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        <h1 style="font-size:30px;font-weight:800;letter-spacing:-0.5px;">{html.escape(brand_name)}</h1>
      </div>
      <div style="font-size:13px;opacity:.8;margin-bottom:4px;">{html.escape(brand_tagline)}</div>
      <div style="font-size:12px;opacity:.65;">Security Assessment Report · {gen_ts}</div>
      {author_line}
    </div>
  </div>

  <!-- ── Meta bar ───────────────────────────────────────── -->
  <div style="background:#1e293b;padding:16px 40px;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;">
    <div><div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.7px;margin-bottom:4px;">Target</div>
      <div style="font-size:13px;color:#e2e8f0;word-break:break-all;">{html.escape(report.target)}</div></div>
    <div><div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.7px;margin-bottom:4px;">Scan Mode</div>
      <div style="font-size:13px;color:#e2e8f0;">{report.scan_mode.value.title()}</div></div>
    <div><div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.7px;margin-bottom:4px;">Scan Started</div>
      <div style="font-size:13px;color:#e2e8f0;">{scan_ts}</div></div>
    <div><div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.7px;margin-bottom:4px;">Duration</div>
      <div style="font-size:13px;color:#e2e8f0;">{report.duration_seconds:.1f}s</div></div>
    <div><div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.7px;margin-bottom:4px;">Issues Found</div>
      <div style="font-size:13px;">
        <span style="color:#f87171;font-weight:700;">{report.critical_count} critical</span> ·
        <span style="color:#fb923c;font-weight:700;">{report.high_count} high</span> ·
        <span style="color:#fbbf24;font-weight:700;">{report.medium_count} medium</span> ·
        <span style="color:#60a5fa;font-weight:700;">{report.low_count} low</span>
      </div></div>
  </div>

  <!-- ── Overall Score ──────────────────────────────────── -->
  <div style="padding:48px 40px;text-align:center;border-bottom:1px solid #e2e8f0;">
    <div class="score-ring" style="background:{score_color};">
      <div class="score-num">{score}</div>
      <div class="score-den">/ 100</div>
    </div>
    <h2 style="font-size:24px;font-weight:700;color:#1e293b;margin-bottom:8px;">{score_label}</h2>
    <p style="color:#64748b;max-width:520px;margin:0 auto;font-size:14px;">
      {_score_description(score)}
    </p>
  </div>

  <!-- ── Category Scores ────────────────────────────────── -->
  <div style="padding:32px 40px;border-bottom:1px solid #e2e8f0;">
    <h2 style="font-size:18px;font-weight:700;margin-bottom:4px;">Category Scores</h2>
    <p style="font-size:12px;color:#94a3b8;margin-bottom:20px;">Scores are weighted by severity of findings in each category.</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px;">
      {category_scores}
    </div>
  </div>

  <!-- ── OWASP Top 10 ───────────────────────────────────── -->
  <div style="padding:32px 40px;border-bottom:1px solid #e2e8f0;">
    <h2 style="font-size:18px;font-weight:700;margin-bottom:4px;">OWASP Top 10 (2021)</h2>
    <p style="font-size:12px;color:#94a3b8;margin-bottom:20px;">
      {"Active scan coverage included." if report.scan_mode.value != "passive" else "Passive scan only — server-side items require active mode."}
    </p>
    <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
      {owasp_html}
    </div>
  </div>

  <!-- ── Detailed Findings ──────────────────────────────── -->
  <div style="padding:32px 40px;">
    <h2 style="font-size:18px;font-weight:700;margin-bottom:20px;">Detailed Findings</h2>
    {categories_html}
  </div>

  <!-- ── Footer ────────────────────────────────────────── -->
  <div style="background:#0f172a;padding:28px 40px;text-align:center;">
    <div style="margin-bottom:12px;">
      <span class="brand-badge">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        Secured by {html.escape(brand_name)}
      </span>
    </div>
    <div style="font-size:12px;color:#475569;line-height:1.8;">
      Generated by <strong style="color:#94a3b8;">{html.escape(brand_name)} v{report.scanner_version}</strong><br>
      <em style="color:#334155;">This automated report covers common web vulnerabilities. A professional penetration test is recommended for production systems.</em><br>
      <span style="color:#1e40af;font-size:10px;margin-top:4px;display:block;">© {datetime.now().year} {html.escape(brand_name)} — All rights reserved</span>
    </div>
  </div>

</div>

<!-- CrabGuard Watermark -->
<div class="watermark no-print">{html.escape(brand_name)}</div>

</body>
</html>"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(page, encoding="utf-8")
    return str(path)


# ── Helper renderers ──────────────────────────────────────────────────────────

def _render_score_card(cat: CategoryResult) -> str:
    color = cat.status_color
    emoji = _cat_emoji(cat.name)
    return f"""<div class="cat-card" style="border-color:{color}33;">
      <div style="font-size:22px;margin-bottom:4px;">{emoji}</div>
      <div style="font-size:11px;font-weight:700;color:#1e293b;margin-bottom:4px;line-height:1.3;">{html.escape(cat.name)}</div>
      <div style="font-size:24px;font-weight:800;color:{color};">{cat.score}</div>
      <div style="font-size:10px;color:#94a3b8;">/ 100</div>
    </div>"""


def _render_owasp_row(item: str, status: str) -> str:
    color, bg = OWASP_COLORS.get(status, ("#94a3b8", "#f1f5f9"))
    cls = {"PASS": "badge-pass", "WARN": "badge-warn",
           "FAIL": "badge-fail", "N/A": "badge-na"}.get(status, "badge-na")
    is_last = False  # handled by CSS
    return f"""<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid #f1f5f9;background:#fff;">
      <span style="font-size:13px;color:#475569;">{html.escape(item)}</span>
      <span class="badge {cls}">{status}</span>
    </div>"""


def _render_category(cat: CategoryResult) -> str:
    findings_html = "\n".join(_render_finding(f) for f in cat.findings)
    emoji         = _cat_emoji(cat.name)
    badge_cls     = {"PASS": "badge-pass", "WARN": "badge-warn", "FAIL": "badge-fail"}.get(cat.status, "badge-info")

    return f"""<div style="background:#f8fafc;border-radius:14px;margin-bottom:24px;overflow:hidden;border:1px solid #e2e8f0;">
      <div style="padding:16px 20px;background:#fff;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #e2e8f0;">
        <h3 style="font-size:16px;font-weight:700;color:#1e293b;">{emoji} {html.escape(cat.name)}</h3>
        <div style="display:flex;gap:10px;align-items:center;">
          <span style="font-size:13px;color:#94a3b8;">Score: {cat.score}/100</span>
          <span class="badge {badge_cls}">{cat.status}</span>
        </div>
      </div>
      <div style="padding:16px;">
        {findings_html if findings_html else '<p style="font-size:13px;color:#94a3b8;padding:8px;">No findings in this category.</p>'}
      </div>
    </div>"""


def _render_finding(f: Finding) -> str:
    sev_class = f"finding-{f.severity.value}"
    sev_emoji = SEVERITY_EMOJI.get(f.severity, "")
    desc_part = f'<div class="finding-desc">{html.escape(f.description)}</div>' if f.description else ""
    evid_part = f'<div class="finding-evidence">{html.escape(f.evidence)}</div>' if f.evidence else ""
    rem_part  = f'<div class="remediation">💡 {html.escape(f.remediation)}</div>' if f.remediation else ""
    cwe_part  = f'<span style="font-size:10px;color:#94a3b8;margin-left:8px;">{html.escape(f.cwe)}</span>' if f.cwe else ""

    refs = ""
    if f.references:
        links = " · ".join(f'<a href="{html.escape(r)}" style="color:#3b82f6;font-size:11px;">{html.escape(r)}</a>' for r in f.references[:2])
        refs  = f'<div style="margin-top:6px;">{links}</div>'

    return f"""<div class="finding {sev_class}">
      <div class="finding-title">{sev_emoji} {html.escape(f.title)}{cwe_part}</div>
      {desc_part}{evid_part}{rem_part}{refs}
    </div>"""


def _cat_emoji(name: str) -> str:
    mapping = {
        "Security Headers":       "🔒",
        "Cookie Security":        "🍪",
        "TLS / HTTPS":            "🌐",
        "Content Analysis":       "📋",
        "Information Disclosure": "🔍",
        "SQL Injection":          "💉",
        "XSS (Reflected)":        "⚡",
        "Open Redirect":          "↪️",
        "SSRF":                   "🔄",
        "Sensitive File Discovery":"🗂️",
        "Authentication":         "🔑",
    }
    for key, emoji in mapping.items():
        if key.lower() in name.lower():
            return emoji
    return "🛡️"


def _score_description(score: int) -> str:
    if score >= 90:
        return "Excellent! This target demonstrates strong security practices across all tested categories."
    if score >= 75:
        return "Good overall security posture with a few areas that could be hardened further."
    if score >= 50:
        return "Moderate security risk. Several important security controls are missing or misconfigured."
    if score >= 25:
        return "High risk. Multiple critical or high-severity vulnerabilities require immediate attention."
    return "Critical security risk. This target has severe vulnerabilities that expose users and data."
