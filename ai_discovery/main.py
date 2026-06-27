"""
AI Discovery Tool — CLI entrypoint.

Usage:
  ai-discovery scan [OPTIONS]
  python -m ai_discovery.main scan --mock
"""

from __future__ import annotations

import platform
import socket
import sys
import time
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ai_discovery import __version__
from ai_discovery.models import ScanMetadata, ScanReport

app = typer.Typer(
    name="ai-discovery",
    help="Scan this machine for installed AI tools, running models, and AI infrastructure.",
    add_completion=False,
)

console = Console()


def _get_username() -> str:
    try:
        import os
        return os.getlogin()
    except Exception:
        import getpass
        return getpass.getuser()


@app.command()
def scan(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write JSON report to this path."),
    fmt: str = typer.Option("table", "--format", help="Output format: table or json."),
    categories: str = typer.Option(
        "apps,processes,models,packages,gpu",
        "--categories",
        help="Comma-separated categories to scan: apps,processes,models,packages,gpu",
    ),
    model_paths: Optional[str] = typer.Option(
        None, "--model-paths", help="Extra directories to scan for model files (colon-separated)."
    ),
    timeout: int = typer.Option(3, "--timeout", help="HTTP probe timeout in seconds."),
    no_progress: bool = typer.Option(False, "--no-progress", help="Disable progress spinners."),
    mock: bool = typer.Option(False, "--mock", help="Demo mode with synthetic data (works on Linux)."),
    deep: bool = typer.Option(
        False, "--deep",
        help="Full drive scan: walk all drives for model files and find all Python environments. Slow (3-10 min) but finds everything.",
    ),
) -> None:
    """Scan this machine for AI tools, running models, and infrastructure."""

    if mock:
        from ai_discovery.mock_data import make_mock_report
        from ai_discovery.report.terminal import render_report
        from ai_discovery.report.json_export import write_json, to_json_str

        report = make_mock_report()
        if fmt == "json":
            print(to_json_str(report))
        else:
            render_report(report, console)
        if output:
            write_json(report, output)
            console.print(f"\n[dim]Report saved to: {output}[/]")
        return

    if deep:
        console.print("[yellow]Deep scan in progress — this may take 3-10 minutes on large drives.[/]")

    cats = {c.strip().lower() for c in categories.split(",")}

    extra_model_paths: list[str] = []
    if model_paths:
        sep = ";" if sys.platform == "win32" else ":"
        extra_model_paths = [p.strip() for p in model_paths.split(sep) if p.strip()]

    start_time = datetime.now()
    hostname = socket.gethostname()
    username = _get_username()

    metadata = ScanMetadata(
        scan_started_at=start_time,
        hostname=hostname,
        username=username,
        platform=sys.platform,
        windows_version=platform.version() if sys.platform == "win32" else None,
        tool_version=__version__,
        categories_scanned=sorted(cats),
    )

    report = ScanReport(metadata=metadata)
    all_warnings: list[str] = []

    steps = []
    if "apps" in cats:
        steps.append(("Scanning installed applications…", _run_apps, report))
    if "processes" in cats:
        steps.append(("Scanning running AI services…", lambda r: _run_processes(r, timeout), report))
    if "models" in cats:
        steps.append(("Scanning for model files…", lambda r: _run_models(r, extra_model_paths, deep), report))
    if "packages" in cats:
        steps.append(("Scanning Python environments…", lambda r: _run_packages(r, deep), report))
    if "gpu" in cats:
        steps.append(("Detecting GPU hardware…", _run_gpu, report))

    if no_progress:
        for desc, fn, r in steps:
            warnings = fn(r)
            all_warnings.extend(warnings)
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            for desc, fn, r in steps:
                task = progress.add_task(desc, total=None)
                warnings = fn(r)
                all_warnings.extend(warnings)
                progress.remove_task(task)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    report.metadata = metadata.model_copy(update={
        "scan_completed_at": end_time,
        "scan_duration_seconds": duration,
    })

    from ai_discovery.report.terminal import render_report
    from ai_discovery.report.json_export import write_json, to_json_str

    if fmt == "json":
        print(to_json_str(report))
    else:
        render_report(report, console)

    if output:
        write_json(report, output)
        console.print(f"\n[dim]Report saved to: {output}[/]")

    if all_warnings:
        console.print()
        for w in all_warnings[:10]:
            console.print(f"[yellow]Warning:[/] {w}")
        if len(all_warnings) > 10:
            console.print(f"[dim]… and {len(all_warnings) - 10} more warnings[/]")


def _run_apps(report: ScanReport) -> list[str]:
    from ai_discovery.scanner.apps import scan_apps
    apps, warnings = scan_apps()
    report.installed_apps = apps
    return warnings


def _run_processes(report: ScanReport, timeout: int) -> list[str]:
    from ai_discovery.scanner.processes import scan_processes
    services, warnings = scan_processes(http_timeout=timeout)
    report.running_services = services
    return warnings


def _run_models(report: ScanReport, extra_paths: list[str], deep: bool = False) -> list[str]:
    from ai_discovery.scanner.models_scan import scan_models
    files, warnings = scan_models(extra_paths=extra_paths or None, deep=deep)
    report.model_files = files
    return warnings


def _run_packages(report: ScanReport, deep: bool = False) -> list[str]:
    from ai_discovery.scanner.packages import scan_packages
    envs, warnings = scan_packages(deep=deep)
    report.python_environments = envs
    return warnings


def _run_gpu(report: ScanReport) -> list[str]:
    from ai_discovery.scanner.gpu import scan_gpu
    gpus, warnings = scan_gpu()
    report.gpus = gpus
    return warnings


if __name__ == "__main__":
    app()
