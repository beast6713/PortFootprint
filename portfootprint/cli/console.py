"""
PortFootprint Interactive Console Launcher.
Coordinates banner rendering, diagnostic checks, and shell REPL loop.
"""

import sys
from typing import Optional

try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    Console = None  # type: ignore
    RICH_AVAILABLE = False

from portfootprint.cli.banner import PortFootprintBanner
from portfootprint.cli.commands import build_default_command_registry
from portfootprint.cli.doctor import DoctorDiagnostic
from portfootprint.cli.shell import PortFootprintShell


class PortFootprintConsole:
    """Main launcher for the PortFootprint interactive console."""

    def __init__(self) -> None:
        if sys.platform == "win32":
            try:
                if hasattr(sys.stdout, "reconfigure"):
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                if hasattr(sys.stderr, "reconfigure"):
                    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

        self.console = Console() if RICH_AVAILABLE else None
        self.registry = build_default_command_registry()
        self.shell = PortFootprintShell(self.registry, console=self.console)

    def run(self) -> int:
        """Runs startup health check, renders ASCII banner, and launches REPL."""
        status = "READY"
        try:
            status, _ = DoctorDiagnostic.run_diagnostics(console=None)
        except Exception:
            status = "READY"

        # 1. Render ASCII Banner
        PortFootprintBanner.render(console=self.console, status=status)

        # 2. Launch REPL loop
        return self.shell.run_loop()


def launch_console() -> int:
    """Convenience helper to instantiate and run console."""
    console = PortFootprintConsole()
    return console.run()
