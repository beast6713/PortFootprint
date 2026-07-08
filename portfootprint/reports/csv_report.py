"""
CsvReportExporter serializing scan results to flat CSV format.
"""

import csv
import logging

from portfootprint.core.models import ScanResult
from portfootprint.reports.base import BaseReportExporter
from portfootprint.reports.registry import export_registry

logger = logging.getLogger("portfootprint.reports.csv")


@export_registry.register("csv")
class CsvReportExporter(BaseReportExporter):
    """
    CSV Exporter.
    Generates flat tables of scanned ports.
    """
    def export(self, scan_result: ScanResult, output_path: str) -> None:
        headers = ["Port", "State", "Protocol", "Version", "Banner", "Service Name"]

        try:
            with open(output_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(headers)

                for host in scan_result.hosts:
                    for port in host.ports:
                        srv_name = ""
                        proto = "tcp"
                        ver = ""
                        banner = ""

                        if port.service:
                            s = port.service
                            srv_name = s.service_name
                            proto = s.protocol
                            ver = s.version
                            banner = s.banner

                        writer.writerow([
                            port.port,
                            port.state,
                            proto,
                            ver,
                            banner,
                            srv_name
                        ])
            logger.info(f"CSV report successfully exported to '{output_path}'.")
        except OSError as e:
            logger.exception(f"Failed to write CSV report to '{output_path}': {e!s}")
            raise
