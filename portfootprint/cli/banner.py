"""
ASCII Banner and Framework Metadata Display Generator for PortFootprint.
Modeled after professional interactive security consoles.
"""

import os
import sys
from typing import Any, Optional, Tuple

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    Console = None  # type: ignore
    Panel = None  # type: ignore
    Table = None  # type: ignore
    RICH_AVAILABLE = False

from portfootprint.core.version import __version__


class PortFootprintBanner:
    """Renders the Metasploit-style ASCII logo and framework status panel."""

    ASCII_ART = r"""
██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗  ██████╗ ████████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔═══██╗██╔═══██╗╚══██╔══╝
██████╔╝██║   ██║██████╔╝   ██║   █████╗  ██║   ██║██║   ██║   ██║   
██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══╝  ██║   ██║██║   ██║   ██║   
██║     ╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝╚██████╔╝   ██║   
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝  ╚═════╝    ╚═╝   
"""

    @classmethod
    def get_counts(cls) -> tuple[int, int, int]:
        """Dynamically detect loaded protocols, exporters, and scan history count."""
        # 1. Protocols
        try:
            import portfootprint.services.protocols  # noqa: F401
            from portfootprint.services.registry import registry
            protocols_count = len(registry._entries)
        except Exception:
            protocols_count = 11

        # 2. Exporters
        try:
            from portfootprint.reports.registry import export_registry
            exporters_count = len(export_registry.list_formats()) or 3
        except Exception:
            exporters_count = 3

        # 3. History records
        try:
            from portfootprint.core.history import ScanHistoryManager
            hm = ScanHistoryManager()
            history_count = len(hm.get_history())
        except Exception:
            history_count = 0

        return protocols_count, exporters_count, history_count

    @classmethod
    def render(cls, console: Optional[Any] = None, status: str = "READY") -> None:
        """Render banner and metadata display panel to terminal."""
        protocols, exporters, history_count = cls.get_counts()
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        workspace_display = os.path.basename(os.getcwd()) or "Workspace"

        if RICH_AVAILABLE and console:
            console.print(f"[bold cyan]{cls.ASCII_ART}[/bold cyan]")
            console.print("        [bold white]PORTFOOTPRINT TCP SCANNER & FINGERPRINTING ENGINE[/bold white]")
            console.print("                     [bold blue]Enterprise Edition v" + __version__ + "[/bold blue]\n")
            console.print("[dim cyan]──────────────────────────────────────────────────────────────────[/dim cyan]")

            status_color = "bold green" if status == "READY" else ("bold yellow" if status == "WARNING" else "bold red")
            console.print(f"Framework Status  : [{status_color}]{status}[/{status_color}]")
            console.print(f"Release Version   : [bold white]{__version__}[/bold white]")
            console.print(f"Python Runtime    : [bold white]{py_ver}[/bold white]")
            console.print(f"Active Workspace  : [bold yellow]{workspace_display}[/bold yellow]")
            console.print(f"Protocols Loaded  : [bold green]{protocols}[/bold green] (HTTP, HTTPS, SSH, MySQL, Postgres, Redis, etc.)")
            console.print(f"Exporters Ready   : [bold green]{exporters}[/bold green] (JSON, CSV, HTML Dashboard)")
            console.print(f"History Logged    : [bold cyan]{history_count}[/bold cyan] previous scans recorded")
            console.print("[dim cyan]──────────────────────────────────────────────────────────────────[/dim cyan]")
            console.print('Type "[bold cyan]help[/bold cyan]" for command list, "[bold green]local[/bold green]" to scan open ports, or "[bold red]exit[/bold red]" to quit.\n')
        else:
            print(cls.ASCII_ART)
            print("        PORTFOOTPRINT TCP SCANNER & FINGERPRINTING ENGINE")
            print(f"                     Enterprise Edition v{__version__}\n")
            print("─" * 66)
            print(f"Framework Status  : {status}")
            print(f"Release Version   : {__version__}")
            print(f"Python Runtime    : {py_ver}")
            print(f"Active Workspace  : {workspace_display}")
            print(f"Protocols Loaded  : {protocols}")
            print(f"Exporters Ready   : {exporters} (JSON, CSV, HTML)")
            print(f"History Logged    : {history_count} previous scans")
            print("─" * 66)
            print('Type "help" for command list, "local" to scan open ports, or "exit" to quit.\n')
