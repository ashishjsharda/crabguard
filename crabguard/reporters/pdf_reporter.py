"""
CrabGuard – PDF Report Generator
Wraps the HTML report into a PDF with CrabGuard watermark using WeasyPrint.
Falls back gracefully if WeasyPrint is not installed.
"""
from __future__ import annotations
from pathlib import Path

from ..models import ScanReport
from . import html_reporter


def generate(report: ScanReport, output_path: str,
             brand_name: str = "CrabGuard",
             brand_tagline: str = "Enterprise Web Security Scanner",
             report_author: str = "") -> str:
    """
    Generate a PDF report. Requires: pip install weasyprint
    Returns the path to the PDF file.
    """
    try:
        from weasyprint import HTML as WeasyHTML, CSS
    except ImportError:
        raise ImportError(
            "WeasyPrint is required for PDF generation.\n"
            "Install it with: pip install weasyprint"
        )

    # Generate HTML first in a temp location
    html_path = output_path.replace(".pdf", "_tmp.html")
    html_reporter.generate(
        report, html_path, brand_name, brand_tagline, report_author
    )

    # Additional print CSS for watermark
    watermark_css = CSS(string=f"""
    @page {{
        size: A4;
        margin: 20mm 15mm;
    }}
    body {{
        background: white !important;
        padding: 0 !important;
    }}
    .container {{
        box-shadow: none !important;
        border-radius: 0 !important;
        max-width: 100% !important;
        margin: 0 !important;
    }}
    .no-print {{
        display: none !important;
    }}
    /* Watermark via ::before on body */
    body::after {{
        content: "{brand_name}";
        position: fixed;
        bottom: 40mm;
        right: 10mm;
        font-size: 72pt;
        font-weight: 900;
        color: #1e40af;
        opacity: 0.04;
        transform: rotate(-30deg);
        transform-origin: bottom right;
        pointer-events: none;
        z-index: 9999;
        white-space: nowrap;
    }}
    """)

    pdf_path = Path(output_path)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    WeasyHTML(filename=html_path).write_pdf(
        str(pdf_path),
        stylesheets=[watermark_css],
    )

    # Clean up temp HTML
    Path(html_path).unlink(missing_ok=True)

    return str(pdf_path)
