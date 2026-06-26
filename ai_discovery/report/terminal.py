"""
Rich terminal output for ScanReport.
"""

from __future__ import annotations

from collections import defaultdict

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ai_discovery.models import (
    AppCategory,
    GPUVendor,
    ModelFile,
    ScanReport,
)

_CATEGORY_LABELS: dict[AppCategory, str] = {
    AppCategory.LOCAL_LLM: "Local LLM",
    AppCategory.IMAGE_GENERATION: "Image Generation",
    AppCategory.CODE_ASSISTANT: "Code Assistant",
    AppCategory.AI_INFRASTRUCTURE: "AI Infrastructure",
    AppCategory.OTHER: "Other",
}

_VENDOR_COLORS: dict[GPUVendor, str] = {
    GPUVendor.NVIDIA: "green",
    GPUVendor.AMD: "red",
    GPUVendor.INTEL: "blue",
    GPUVendor.UNKNOWN: "dim",
}


def _trunc(s: str, n: int) -> str:
    if not s:
        return ""
    return s if len(s) <= n else f"…{s[-(n-1):]}"


def _short_path(path: str, max_parts: int = 3) -> str:
    if not path:
        return ""
    parts = path.replace("\\", "/").split("/")
    if len(parts) <= max_parts:
        return path
    return "…/" + "/".join(parts[-max_parts:])


def render_report(report: ScanReport, console: Console | None = None) -> None:
    if console is None:
        console = Console()

    meta = report.metadata
    duration = f"{meta.scan_duration_seconds:.1f}s" if meta.scan_duration_seconds else "?"

    # Header
    header = Panel(
        f"[bold cyan]AI Discovery Tool[/] [dim]v{meta.tool_version}[/]\n"
        f"[dim]Scanned [bold]{meta.hostname}[/] in {duration}[/]",
        expand=False,
        border_style="cyan",
    )
    console.print()
    console.print(header)

    # Summary stats
    from ai_discovery.models import _human_size
    total_size = _human_size(report.total_model_size_bytes)
    stats = [
        Panel(f"[bold]{len(report.installed_apps)}[/]\nApps Found", expand=True),
        Panel(f"[bold]{len(report.running_services)}[/]\nRunning", expand=True),
        Panel(f"[bold]{report.total_model_count}[/]\nModel Files", expand=True),
        Panel(f"[bold]{total_size}[/]\nTotal Size", expand=True),
    ]
    console.print(Columns(stats))

    # ------------------------------------------------------------------
    # GPU Hardware
    # ------------------------------------------------------------------
    if report.gpus:
        console.print(Rule("[bold]GPU Hardware[/]", style="cyan"))
        gpu_table = Table(show_header=True, header_style="bold cyan", show_lines=False, expand=True)
        gpu_table.add_column("GPU / CPU", style="bold")
        gpu_table.add_column("VRAM", justify="right")
        gpu_table.add_column("CUDA", justify="center")
        gpu_table.add_column("ROCm", justify="center")
        gpu_table.add_column("Driver")
        gpu_table.add_column("Source", style="dim")

        for gpu in report.gpus:
            color = _VENDOR_COLORS.get(gpu.vendor, "")
            cuda_check = "[green]✓[/]" if gpu.supports_cuda else ""
            rocm_check = "[green]✓[/]" if gpu.supports_rocm else ""
            gpu_table.add_row(
                f"[{color}]{gpu.name}[/]",
                gpu.vram_human or "—",
                cuda_check,
                rocm_check,
                gpu.driver_version or "—",
                gpu.detection_source,
            )
        console.print(gpu_table)

    # ------------------------------------------------------------------
    # Installed AI Applications
    # ------------------------------------------------------------------
    console.print(Rule("[bold]Installed AI Applications[/]", style="cyan"))
    if not report.installed_apps:
        console.print("[dim]  No installed AI applications detected.[/]")
    else:
        app_table = Table(show_header=True, header_style="bold cyan", show_lines=False, expand=True)
        app_table.add_column("Application", style="bold")
        app_table.add_column("Version")
        app_table.add_column("Category")
        app_table.add_column("Install Path")
        app_table.add_column("Detected Via", style="dim")

        by_cat: dict[AppCategory, list] = defaultdict(list)
        for app in report.installed_apps:
            by_cat[app.category].append(app)

        for cat in AppCategory:
            for app in by_cat.get(cat, []):
                app_table.add_row(
                    app.name,
                    app.version or "—",
                    _CATEGORY_LABELS.get(app.category, app.category.value),
                    _short_path(app.install_path or "", 3),
                    ", ".join(m.value for m in app.detection_methods),
                )
        console.print(app_table)

    # ------------------------------------------------------------------
    # Running AI Services
    # ------------------------------------------------------------------
    console.print(Rule("[bold]Running AI Services[/]", style="cyan"))
    if not report.running_services:
        console.print("[dim]  No running AI services detected.[/]")
    else:
        svc_table = Table(show_header=True, header_style="bold cyan", show_lines=False, expand=True)
        svc_table.add_column("Service", style="bold")
        svc_table.add_column("PID", justify="right", style="dim")
        svc_table.add_column("Port", justify="right")
        svc_table.add_column("Status", justify="center")
        svc_table.add_column("Loaded Models")

        for svc in report.running_services:
            status = "[green]● live[/]" if svc.is_alive else "[yellow]● process[/]"
            models_str = ", ".join(svc.loaded_models[:3])
            if len(svc.loaded_models) > 3:
                models_str += f" +{len(svc.loaded_models) - 3} more"
            svc_table.add_row(
                svc.name,
                str(svc.pid) if svc.pid else "—",
                str(svc.port) if svc.port else "—",
                status,
                models_str or "—",
            )
        console.print(svc_table)

    # ------------------------------------------------------------------
    # AI Model Files
    # ------------------------------------------------------------------
    console.print(Rule("[bold]AI Model Files[/]", style="cyan"))
    if not report.model_files:
        console.print("[dim]  No AI model files found.[/]")
    else:
        # Summary by type
        from ai_discovery.models import _human_size
        by_type: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))
        for mf in report.model_files:
            count, total = by_type[mf.model_type]
            by_type[mf.model_type] = (count + 1, total + mf.size_bytes)

        type_table = Table(show_header=True, header_style="bold", show_lines=False)
        type_table.add_column("Model Type")
        type_table.add_column("Count", justify="right")
        type_table.add_column("Total Size", justify="right")
        for mtype, (cnt, sz) in sorted(by_type.items(), key=lambda x: -x[1][1]):
            type_table.add_row(mtype, str(cnt), _human_size(sz))
        console.print(type_table)

        # Top 20 by size
        console.print()
        top_files = report.model_files[:20]
        file_table = Table(show_header=True, header_style="bold", show_lines=False, expand=True)
        file_table.add_column("Filename")
        file_table.add_column("Size", justify="right")
        file_table.add_column("Type")
        file_table.add_column("Location", style="dim")

        for mf in top_files:
            file_table.add_row(
                _trunc(mf.filename, 50),
                mf.size_human,
                mf.model_type,
                _short_path(str(mf.path), 2),
            )
        console.print(file_table)

    # ------------------------------------------------------------------
    # Python Environments
    # ------------------------------------------------------------------
    console.print(Rule("[bold]Python Environments with AI Packages[/]", style="cyan"))
    if not report.python_environments:
        console.print("[dim]  No AI Python packages detected.[/]")
    else:
        max_envs = 5
        shown = report.python_environments[:max_envs]
        hidden = len(report.python_environments) - max_envs

        for env in shown:
            env_label = f"[bold]{_short_path(env.interpreter_path, 4)}[/]"
            env_label += f"  [dim]{env.python_version}  ({env.environment_type}"
            if env.environment_name:
                env_label += f": {env.environment_name}"
            env_label += ")[/]"
            console.print(env_label)

            pkg_table = Table(show_header=False, show_lines=False, padding=(0, 2))
            pkg_table.add_column("Package", style="cyan")
            pkg_table.add_column("Version", style="dim")
            pkg_table.add_column("Category", style="dim")
            pkg_table.add_column("GPU", justify="center")

            by_cat_pkg: dict[str, list] = defaultdict(list)
            for pkg in env.packages:
                by_cat_pkg[pkg.category].append(pkg)

            for cat_name in sorted(by_cat_pkg):
                for pkg in sorted(by_cat_pkg[cat_name], key=lambda p: p.name):
                    gpu_str = "[green]✓[/]" if pkg.has_gpu_support else ""
                    pkg_table.add_row(pkg.name, pkg.version, cat_name, gpu_str)

            console.print(pkg_table)
            console.print()

        if hidden > 0:
            console.print(f"[dim]  … and {hidden} more environment(s) with AI packages[/]")

    # Footer
    if report.metadata.scan_completed_at:
        console.print(Rule(style="dim"))
        console.print(
            f"[dim]Scan completed at {report.metadata.scan_completed_at.strftime('%Y-%m-%d %H:%M:%S')}[/]"
        )
