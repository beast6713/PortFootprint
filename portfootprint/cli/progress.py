"""
Console progress visualizer utilizing carriage return overlays.
"""

import sys
from typing import Any


class ConsoleProgressRenderer:
    """
    Renders terminal-friendly text progress indicators for scans.
    """
    def __init__(self, bar_width: int = 30) -> None:
        self.bar_width = bar_width

    def render(self, stats: dict[str, Any]) -> None:
        """
        Prints a text-based progress bar on sys.stdout using carriage returns.
        """
        completed = stats.get("completed", 0)
        total = stats.get("total", 0)
        percent = stats.get("percent", 0.0)
        active = stats.get("active_workers", 0)

        # Build visual progress bar
        filled_length = round(self.bar_width * completed / float(total)) if total > 0 else 0

        bar = "=" * filled_length + " " * (self.bar_width - filled_length)

        # Format string carriage return output
        sys.stdout.write(
            f"\rScanning: [{bar}] {percent:.1f}% "
            f"(Completed {completed}/{total}, {active} workers active)"
        )
        sys.stdout.flush()

    def clear(self) -> None:
        """Clears the terminal line to avoid trace outputs overlap."""
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
