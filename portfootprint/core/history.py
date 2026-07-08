"""
ScanHistoryManager maintaining local execution history logs of previous scans.
"""

import datetime
import json
import logging
import os
from typing import Any

from portfootprint.core.statistics import ScanStatistics

logger = logging.getLogger("portfootprint.core.history")


class ScanHistoryManager:
    """
    Manages loading and appending scan execution run metrics to a local history log.
    Saves history to a local JSON file inside the working directory.
    """
    def __init__(self, history_file: str = ".portfootprint_history.json") -> None:
        if "\x00" in history_file:
            raise ValueError("Null bytes are not allowed in history file paths.")
        abs_path = os.path.abspath(history_file)
        real_path = os.path.realpath(abs_path)

        forbidden_prefixes = [
            "/etc", "/bin", "/sbin", "/boot", "/dev", "/sys", "/proc", "/lib",
            "C:\\Windows", "C:\\SystemVolumeInformation"
        ]
        for prefix in forbidden_prefixes:
            if real_path.startswith(prefix) or real_path.lower().startswith(prefix.lower()):
                raise PermissionError("Access forbidden to system directories.")
        self.history_file = real_path

    def _load_history(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.history_file):
            return []
        try:
            with open(self.history_file, encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return []
                data = json.loads(content)
                if isinstance(data, list):
                    return data
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"History file corrupted or unreadable. Resetting. Error: {e!s}")
        return []

    def _save_history(self, history: list[dict[str, Any]]) -> None:
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=4, ensure_ascii=False)
        except OSError as e:
            logger.exception(f"Failed to write history file at '{self.history_file}': {e!s}")

    def add_entry(self, target: str, stats: ScanStatistics, report_paths: dict[str, str]) -> None:
        """Appends a new scan entry with current timestamp to history records."""
        history = self._load_history()

        entry = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "summary": {
                "total_ports": stats.total_ports,
                "open": stats.open_count,
                "closed": stats.closed_count,
                "filtered": stats.filtered_count,
                "unknown": stats.unknown_count,
                "services_detected": stats.services_detected
            },
            "reports": report_paths
        }

        history.append(entry)
        self._save_history(history)

    def get_history(self) -> list[dict[str, Any]]:
        """Retrieves all previous scan records sorted by timestamp descending."""
        history = self._load_history()
        # Sort newest first
        history.reverse()
        return history
