#!/usr/bin/env python3
"""Command-line interface for the AI Agent Security Scanner.

Usage:
    python cli.py scan --path ./my_agent/ --output report.md
    python cli.py scan --endpoint http://localhost:8000 --dynamic
    python cli.py scan --path ./agent.py --framework langchain
    python cli.py catalog
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from agent_scanner.config import Framework, ScanMode, ScannerConfig
from agent_scanner.scanner import AgentSecurityScanner, ScanReport
from agent_scanner.reporting.generator import ReportGenerator
from agent_scanner.reporting.severity import severity_color, severity_label
from agent_scanner.vulnerabilities.catalog import VulnerabilityCatalog


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="agent-scanner",
        description="AI Agent Security Scanner - Static and dynamic security analysis for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument(
        "--path", "-p",
        type=str,
        help="Path to Python file or directory to scan",
    )
    scan_parser.add_argument(
        "--endpoint", "-e",
        type=str,
        help="Agent HTTP endpoint for dynamic analysis",
    )
    scan_parser.add_argument(
        "--framework", "-f",
        type=str,
        choices=["langchain", "crewai", "autogen", "generic"],
        default="generic",
        help="Target AI framework (default: generic)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path for the report",
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        choices=["markdown", "json", "summary"],
        default="markdown",
        help="Report format (default: markdown)",
    )
    scan_parser.add_argument(
        "--dynamic",
        action="store_true",
        help="Enable dynamic analysis (requires --endpoint)",
    )
    scan_parser.add_argument(
        "--severity",
        type=float,
        default=0.0,
        help="Minimum severity threshold to report (0-10)",
    )

    # Catalog command
    subparsers.add_parser("catalog", help="Display the vulnerability catalog")

    return parser


def display_findings(report: ScanReport) -> None:
    """Display scan findings using Rich formatting."""
    if not RICH_AVAILABLE:
        print(report.summary())
        return

    console = Console()

    # Header panel
    risk = report.risk_score
    if risk >= 9.0:
        risk_style = "bold red"
    elif risk >= 7.0:
        risk_style = "bold orange1"
    elif risk >= 4.0:
        risk_style = "bold yellow"
    else:
        risk_style = "bold green"

    console.print(Panel(
        f"[bold]AI Agent Security Scanner[/bold]\n\n"
        f"Files scanned: {report.files_scanned}\n"
        f"Duration: {report.scan_duration_seconds:.2f}s\n"
        f"Risk score: [{risk_style}]{risk:.1f}/10[/{risk_style}]",
        title="Scan Results",
        border_style="blue",
    ))

    # Severity distribution table
    dist_table = Table(title="Severity Distribution")
    dist_table.add_column("Severity", style="bold")
    dist_table.add_column("Count", justify="right")
    dist_table.add_row("[red]Critical[/red]", str(report.critical_count))
    dist_table.add_row("[orange1]High[/orange1]", str(report.high_count))
    dist_table.add_row("[yellow]Medium[/yellow]", str(report.medium_count))
    dist_table.add_row("[blue]Low[/blue]", str(report.low_count))
    dist_table.add_row("[bold]Total[/bold]", f"[bold]{len(report.findings)}[/bold]")
    console.print(dist_table)
    console.print()

    # Findings table
    if report.findings:
        findings_table = Table(title="Findings", show_lines=True)
        findings_table.add_column("#", style="dim", width=4)
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("ID", width=12)
        findings_table.add_column("Title", min_width=30)
        findings_table.add_column("Location", width=30)

        sorted_findings = sorted(
            report.findings,
            key=lambda f: f.severity_score,
            reverse=True,
        )

        for i, finding in enumerate(sorted_findings, 1):
            sev = severity_label(finding.severity_score)
            color = severity_color(finding.severity_score)
            location = ""
            if finding.file_path:
                location = finding.file_path
                if finding.line_number:
                    location += f":{finding.line_number}"

            findings_table.add_row(
                str(i),
                f"[{color}]{sev}[/{color}]",
                finding.vuln_id,
                finding.title,
                location,
            )

        console.print(findings_table)
    else:
        console.print("[green]No security vulnerabilities detected.[/green]")


def display_catalog() -> None:
    """Display the vulnerability catalog."""
    catalog = VulnerabilityCatalog()

    if not RICH_AVAILABLE:
        for entry in catalog.all_entries():
            print(f"{entry.vuln_id}: {entry.name} [{entry.severity}]")
            print(f"  {entry.description}")
            print()
        return

    console = Console()
    table = Table(title="AI Agent Vulnerability Catalog", show_lines=True)
    table.add_column("ID", style="bold", width=12)
    table.add_column("Name", width=28)
    table.add_column("Severity", width=10)
    table.add_column("Score", justify="right", width=6)
    table.add_column("Description", min_width=40)

    for entry in catalog.all_entries():
        color = severity_color(entry.severity_score)
        table.add_row(
            entry.vuln_id,
            entry.name,
            f"[{color}]{entry.severity}[/{color}]",
            f"{entry.severity_score}",
            entry.description,
        )

    console.print(table)


def run_scan(args: argparse.Namespace) -> int:
    """Execute a security scan based on CLI arguments."""
    if not args.path and not args.endpoint:
        print("Error: --path or --endpoint is required", file=sys.stderr)
        return 1

    framework_map = {
        "langchain": Framework.LANGCHAIN,
        "crewai": Framework.CREWAI,
        "autogen": Framework.AUTOGEN,
        "generic": Framework.GENERIC,
    }

    config = ScannerConfig(
        mode=ScanMode.FULL if args.dynamic else ScanMode.STATIC,
        framework=framework_map.get(args.framework, Framework.GENERIC),
        severity_threshold=args.severity,
        output_format=args.format,
    )

    scanner = AgentSecurityScanner(config=config)
    generator = ReportGenerator()

    if RICH_AVAILABLE:
        console = Console()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)

            if args.path and args.dynamic and args.endpoint:
                report = scanner.full_scan(args.path, endpoint=args.endpoint)
            elif args.path:
                report = scanner.scan_code(args.path)
            else:
                report = scanner.scan_agent(args.endpoint)

            progress.update(task, completed=True)
    else:
        print("Scanning...")
        if args.path and args.dynamic and args.endpoint:
            report = scanner.full_scan(args.path, endpoint=args.endpoint)
        elif args.path:
            report = scanner.scan_code(args.path)
        else:
            report = scanner.scan_agent(args.endpoint)

    # Display results
    display_findings(report)

    # Write report file
    if args.output:
        if args.format == "json":
            content = generator.generate_json(report)
        elif args.format == "summary":
            content = generator.generate_summary(report)
        else:
            content = generator.generate_markdown(report)

        Path(args.output).write_text(content, encoding="utf-8")
        print(f"\nReport written to: {args.output}")

    return 1 if report.critical_count > 0 else 0


def main() -> int:
    """CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "scan":
        return run_scan(args)
    elif args.command == "catalog":
        display_catalog()
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
