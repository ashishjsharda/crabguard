"""
CrabGuard - CLI Entry Point
Usage: crabguard scan https://example.com [OPTIONS]
"""
from __future__ import annotations
import sys
from datetime import datetime
from pathlib import Path

try:
    import click
except ImportError:
    print("Install click: pip install click", file=sys.stderr)
    sys.exit(1)

from .config import CrabGuardConfig
from .models import ScanMode
from .scanner import CrabGuardScanner

BANNER = """
  CrabGuard - Enterprise Web Security Scanner v1.0.0
  https://crabguard.io
  ----------------------------------------------------------
"""


@click.group()
def cli():
    """CrabGuard - Enterprise Web Security Scanner"""
    pass


@cli.command()
@click.argument("target")
@click.option("--mode", "-m", default="passive",
              type=click.Choice(["passive", "active", "full"]),
              help="Scan mode. 'active'/'full' probe the target (requires --consent).")
@click.option("--output", "-o", default=None,
              help="Output file path (auto-named if omitted).")
@click.option("--format", "-f", default="html",
              type=click.Choice(["html", "pdf", "json"]),
              help="Report format.")
@click.option("--consent", is_flag=True, default=False,
              help="Confirm you have permission to actively scan this target.")
@click.option("--api-key", "-k", default=None, envvar="CRABGUARD_API_KEY",
              help="CrabGuard Pro API key. Or set env var CRABGUARD_API_KEY.")
@click.option("--proxy", default=None,
              help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp Suite).")
@click.option("--timeout", default=10, type=int, help="Request timeout in seconds.")
@click.option("--author", default="", help="Company/author name for the report.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress progress output.")
def scan(target, mode, output, format, consent, api_key, proxy, timeout, author, quiet):
    """
    Scan a target URL for security vulnerabilities.

    \b
    Examples:
      crabguard scan https://example.com
      crabguard scan https://example.com --mode full --consent --api-key cg_live_...
      crabguard scan https://example.com --format json --quiet
      crabguard scan https://example.com --proxy http://127.0.0.1:8080
    """
    if not quiet:
        click.echo(BANNER)

    if mode in ("active", "full") and not consent:
        click.echo(click.style(
            "  Warning: Active scan requires --consent flag.\n"
            "  Only scan targets you own or have written permission to test.\n"
            "  Add --consent to proceed.",
            fg="yellow"
        ))
        sys.exit(1)

    config = CrabGuardConfig(
        api_key=api_key,
        active_consent=consent,
        proxy=proxy,
        timeout=timeout,
        report_author=author,
    )

    scanner = CrabGuardScanner(
        target=target,
        mode=ScanMode(mode),
        config=config,
        verbose=not quiet,
    )

    if not quiet:
        click.echo(f"  Target : {target}")
        click.echo(f"  Mode   : {mode}")
        click.echo(f"  Format : {format}")
        click.echo()

    report = scanner.scan()

    if not output:
        from urllib.parse import urlparse
        hostname = urlparse(target).hostname or "scan"
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        ext = {"html": ".html", "pdf": ".pdf", "json": ".json"}[format]
        output = f"crabguard-{hostname}-{ts}{ext}"

    saved = scanner.save_report(report, output, fmt=format)

    if not quiet:
        score = report.overall_score
        color = "green" if score >= 75 else "yellow" if score >= 50 else "red"
        click.echo()
        click.echo(f"  Score    : " + click.style(f"{score}/100  {report.score_label}", fg=color))
        click.echo(f"  Critical : {report.critical_count}  High : {report.high_count}  "
                   f"Medium : {report.medium_count}  Low : {report.low_count}")
        click.echo(f"  Report   : {Path(saved).name}")
        click.echo()

    sys.exit(0 if report.critical_count == 0 and report.high_count == 0 else 1)


@cli.command()
@click.argument("target")
@click.option("--output", "-o", default="crabguard-report.html")
@click.option("--author", default="")
def quick(target, output, author):
    """Quick passive scan - no active probing, fastest option."""
    ctx = click.get_current_context()
    ctx.invoke(scan, target=target, mode="passive", output=output,
               format="html", consent=False, api_key=None,
               proxy=None, timeout=10, author=author, quiet=False)


def main():
    cli()


if __name__ == "__main__":
    main()
