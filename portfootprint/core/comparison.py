"""
ScanComparer module comparing port scan results between two execution periods.
"""

import json
import logging
from typing import Any

logger = logging.getLogger("portfootprint.core.comparison")


class ScanComparer:
    """
    Compares two JSON scan reports to discover changes in port states and services.
    Useful for highlighting security changes or unauthorized open service vectors.
    """
    def _load_report(self, file_path: str) -> dict[str, Any]:
        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                raise ValueError("JSON content is not a dictionary.")
        except (json.JSONDecodeError, OSError, ValueError) as e:
            logger.exception(f"Failed to load comparison source file '{file_path}': {e!s}")
            raise ValueError(f"Invalid or missing JSON report file: {file_path}") from e

    def _extract_open_ports(self, report_dict: dict[str, Any]) -> dict[int, dict[str, Any]]:
        """Extracts open ports and their service mappings from report dict."""
        open_ports: dict[int, dict[str, Any]] = {}
        hosts = report_dict.get("hosts", [])

        for host in hosts:
            for port_info in host.get("ports", []):
                state = port_info.get("state", "").upper()
                if state == "OPEN":
                    p = port_info.get("port")
                    srv = port_info.get("service") or {}
                    open_ports[p] = {
                        "service_name": srv.get("service_name", "Unknown"),
                        "version": srv.get("version", ""),
                        "banner": srv.get("banner", "")
                    }
        return open_ports

    def compare_files(self, file_path_old: str, file_path_new: str) -> dict[str, Any]:
        """
        Loads two report files and computes differential changes.
        """
        old_data = self._load_report(file_path_old)
        new_data = self._load_report(file_path_new)

        old_open = self._extract_open_ports(old_data)
        new_open = self._extract_open_ports(new_data)

        added: list[dict[str, Any]] = []
        removed: list[dict[str, Any]] = []
        changed: list[dict[str, Any]] = []

        # Find new/changed ports
        for p, new_meta in new_open.items():
            if p not in old_open:
                added.append({
                    "port": p,
                    "service_name": new_meta["service_name"],
                    "version": new_meta["version"]
                })
            else:
                old_meta = old_open[p]
                srv_changed = old_meta["service_name"] != new_meta["service_name"]
                ver_changed = old_meta["version"] != new_meta["version"]

                if srv_changed or ver_changed:
                    changed.append({
                        "port": p,
                        "old_service": old_meta["service_name"],
                        "new_service": new_meta["service_name"],
                        "old_version": old_meta["version"],
                        "new_version": new_meta["version"]
                    })

        # Find removed ports (open previously, but closed/filtered now)
        for p, old_meta in old_open.items():
            if p not in new_open:
                removed.append({
                    "port": p,
                    "service_name": old_meta["service_name"],
                    "version": old_meta["version"]
                })

        return {
            "old_target": old_data.get("target", "Unknown"),
            "new_target": new_data.get("target", "Unknown"),
            "old_timestamp": old_data.get("start_time", 0.0),
            "new_timestamp": new_data.get("start_time", 0.0),
            "added": sorted(added, key=lambda x: x["port"]),
            "removed": sorted(removed, key=lambda x: x["port"]),
            "changed": sorted(changed, key=lambda x: x["port"])
        }
