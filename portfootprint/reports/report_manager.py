"""
ReportManager class coordinating exports execution for multiple formats.
"""

import logging
import os

from portfootprint.core.models import ScanResult
from portfootprint.reports.registry import export_registry

logger = logging.getLogger("portfootprint.reports.manager")


class ReportManager:
    """
    Orchestrates report generation across multiple format requirements.
    Resolves targets using the ExportRegistry interface.
    """
    def __init__(self, requested_reports: dict[str, str]) -> None:
        # Dictionary mapping format name (e.g. 'json') to file destination path
        self.requested_reports = requested_reports

    def generate_reports(self, scan_result: ScanResult) -> None:
        """
        Loops through all requested reports, fetches exporters, and writes files.
        Catches file path or directory write errors.
        """
        for fmt, path in self.requested_reports.items():
            if not path:
                continue

            try:
                # 1. Check for null byte injection
                if "\x00" in path:
                    raise ValueError("Null bytes are not allowed in path names.")

                # 2. Resolve canonical absolute path
                abs_path = os.path.abspath(path)
                real_path = os.path.realpath(abs_path)

                # 3. Safeguard against writing to critical system directories
                forbidden_prefixes = [
                    "/etc", "/bin", "/sbin", "/boot", "/dev", "/sys", "/proc", "/lib",
                    "C:\\Windows", "C:\\SystemVolumeInformation"
                ]
                for prefix in forbidden_prefixes:
                    if real_path.startswith(prefix) or real_path.lower().startswith(prefix.lower()):
                        raise PermissionError(f"Writing to system directory '{prefix}' is forbidden.")

                # Resolve directory and ensure it exists
                dir_name = os.path.dirname(real_path)
                if dir_name and not os.path.exists(dir_name):
                    os.makedirs(dir_name, exist_ok=True)

                # Fetch exporter class from ExportRegistry
                exporter_cls = export_registry.get_exporter(fmt)
                exporter = exporter_cls()

                logger.info(f"Generating '{fmt.upper()}' report at '{real_path}'...")
                exporter.export(scan_result, real_path)
            except KeyError as e:
                logger.exception(f"Unsupported report format requested: {e!s}")
            except (ValueError, PermissionError) as e:
                logger.exception(f"Security validation failed for path '{path}': {e!s}")
            except OSError as e:
                logger.exception(f"System IO error occurred creating directories for '{path}': {e!s}")
            except Exception as e:
                logger.exception(f"An unexpected error occurred during '{fmt}' report generation: {e!s}")
