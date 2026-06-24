#!/usr/bin/env python3
"""Command-line interface for IAM Security Scanner."""

import logging
import sys
import traceback

import click
from rich.console import Console

from .scanner import IAMSecurityScanner
from . import __version__

# Configure logging format
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.WARNING,
)

console = Console()

# ASCII Art Banner
BANNER = """[bold cyan]╔══════════════════════════════════════════════════════════╗
║              IAM Security Scanner                        ║
║      Comprehensive IAM Security Auditing                 ║
╚══════════════════════════════════════════════════════════╝[/bold cyan]"""


def print_banner():
    """Print the ASCII art banner."""
    console.print(BANNER)
    console.print(
        f"[dim]  Version {__version__} | "
        "https://github.com/TocConsulting/"
        "iam-security-scanner[/dim]\n"
    )


# ====================================================================
# SHARED OPTIONS (composable decorators)
# ====================================================================


def shared_aws_options(f):
    """AWS connection options shared across commands."""
    f = click.option(
        "-r", "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )(f)
    f = click.option(
        "-p", "--profile",
        default=None,
        help="AWS profile name",
    )(f)
    return f


def shared_output_options(f):
    """Output options shared across commands."""
    f = click.option(
        "-o", "--output-dir",
        default="./output",
        help="Directory for output files (default: ./output)",
    )(f)
    f = click.option(
        "-f", "--output-format",
        type=click.Choice(
            ["json", "csv", "html", "all"],
            case_sensitive=False,
        ),
        default="all",
        help="Report format (default: all)",
    )(f)
    return f


def shared_performance_options(f):
    """Performance and logging options shared across commands."""
    f = click.option(
        "-w", "--max-workers",
        default=6,
        type=click.IntRange(1, 10),
        help="Worker threads for parallel processing "
        "(default: 6)",
    )(f)
    f = click.option(
        "-q", "--quiet",
        is_flag=True,
        help="Suppress console output except errors",
    )(f)
    f = click.option(
        "-d", "--debug",
        is_flag=True,
        help="Enable debug logging",
    )(f)
    return f


def shared_options(f):
    """Apply all shared options to a command."""
    f = shared_aws_options(f)
    f = shared_output_options(f)
    f = shared_performance_options(f)
    return f


# ====================================================================
# MAIN CLI GROUP
# ====================================================================


class CustomGroup(click.Group):
    """Custom Click group with banner display."""

    def format_help(self, ctx, formatter):
        """Write the help into the formatter with banner."""
        print_banner()
        super().format_help(ctx, formatter)


@click.group(
    cls=CustomGroup,
    context_settings=dict(
        help_option_names=["-h", "--help"]
    ),
)
@click.version_option(
    version=__version__,
    prog_name="IAM Security Scanner",
)
def cli():
    """
    Comprehensive AWS IAM security scanner for vulnerability
    detection and multi-framework compliance auditing.

    \b
    FRAMEWORKS
    ══════════════════════════════════════════════════════════
      AWS-FSBP, CIS v5.0.0, PCI DSS v4.0.1, HIPAA, SOC 2,
      ISO 27001:2022, ISO 27017, ISO 27018, GDPR, NIST 800-53

    \b
    QUICK START
    ══════════════════════════════════════════════════════════
      Scan account:        iam-security-scanner security
      Use AWS profile:     iam-security-scanner security -p prod
      Specific region:     iam-security-scanner security -r eu-west-1
      Compliance only:     iam-security-scanner security --compliance-only
      JSON only:           iam-security-scanner security -f json

    \b
    MORE INFO
    ══════════════════════════════════════════════════════════
      Run COMMAND --help for detailed options
      Docs: https://github.com/TocConsulting/iam-security-scanner
    """
    pass


# ====================================================================
# SECURITY COMMAND
# ====================================================================


@cli.command()
@click.option(
    "--compliance-only",
    is_flag=True,
    help="Show only compliance results in console output",
)
@shared_options
def security(
    compliance_only, region, profile, output_dir,
    output_format, max_workers, quiet, debug,
):
    """
    Scan IAM configuration for security vulnerabilities
    and compliance issues.

    \b
    Runs 44 security checks across 7 categories and
    evaluates compliance against 10 frameworks with
    128 controls.

    \b
    EXAMPLES:
      iam-security-scanner security
      iam-security-scanner security -p prod -r us-west-2
      iam-security-scanner security --compliance-only
      iam-security-scanner security -f html -o ./reports
      iam-security-scanner security -w 3 -q
    """
    # Configure logging
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger(
            "iam_security_scanner"
        ).setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)

    if not quiet:
        print_banner()
        console.print(
            "[bold cyan]Starting IAM security "
            "analysis...[/bold cyan]\n"
        )

    try:
        # Initialize scanner
        scanner = IAMSecurityScanner(
            region=region,
            profile=profile,
            output_dir=output_dir,
            max_workers=max_workers,
        )

        # Perform scan
        result = scanner.scan()

        if not result:
            console.print(
                "[red]No results generated[/red]"
            )
            sys.exit(2)

        # Generate reports
        report_files = scanner.generate_reports(
            result, output_format,
        )

        if not quiet:
            scanner.print_summary(result)

            console.print(
                "\n[bold green]Reports "
                "Generated:[/bold green]"
            )
            for report_type, file_path in (
                report_files.items()
            ):
                console.print(
                    f"  {report_type.upper()}: {file_path}"
                )

        if not quiet:
            console.print(
                "\n[bold green]Security scan completed "
                "successfully![/bold green]"
            )
            console.print(
                f"[dim]Reports saved to: {output_dir}[/dim]"
            )

        # Exit code based on critical findings
        critical = result.get("summary", {}).get(
            "critical_findings", 0
        )
        if critical > 0:
            sys.exit(1)

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Scan interrupted by user[/yellow]"
        )
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        if debug:
            console.print(
                f"[red]{traceback.format_exc()}[/red]"
            )
        sys.exit(2)


# For backward compatibility with entry point
main = cli


if __name__ == "__main__":
    cli()
