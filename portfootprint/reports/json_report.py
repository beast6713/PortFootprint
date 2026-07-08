"""
JsonReportExporter serializing scan results to JSON format.
"""

import json
import logging
from typing import Any

from portfootprint.core.models import ScanResult
from portfootprint.core.statistics import ScanStatistics
from portfootprint.reports.base import BaseReportExporter
from portfootprint.reports.registry import export_registry

logger = logging.getLogger("portfootprint.reports.json")


@export_registry.register("json")
class JsonReportExporter(BaseReportExporter):
    """
    JSON Exporter.
    Generates structured JSON detailing hosts, scan metrics, and services.
    """
    def export(self, scan_result: ScanResult, output_path: str) -> None:
        stats = ScanStatistics.calculate(scan_result)

        # Build serializable dictionary
        report_data: dict[str, Any] = {
            "scanner": "PortFootprint",
            "target": scan_result.target,
            "resolved_ip": scan_result.resolved_ip,
            "start_time": scan_result.start_time,
            "end_time": scan_result.end_time,
            "duration": scan_result.duration,
            "statistics": {
                "total_ports": stats.total_ports,
                "open": stats.open_count,
                "closed": stats.closed_count,
                "filtered": stats.filtered_count,
                "unknown": stats.unknown_count,
                "scan_speed_ports_per_sec": stats.scan_speed,
                "services_detected": stats.services_detected,
                "most_common_protocol": stats.most_common_protocol,
            },
            "hosts": []
        }

        for host in scan_result.hosts:
            host_data: dict[str, Any] = {
                "target": host.target,
                "ip_address": host.ip_address,
                "ports": []
            }

            for port in host.ports:
                port_data = {
                    "port": port.port,
                    "state": port.state,
                    "reason": port.reason,
                    "duration": port.duration,
                    "service": None
                }

                if port.service:
                    s = port.service
                    port_data["service"] = {
                        "service_name": s.service_name,
                        "protocol": s.protocol,
                        "version": s.version,
                        "banner": s.banner,
                        "headers": s.headers,
                        "certificate": s.certificate,
                        "title": s.title,
                        "extra_details": s.extra_details
                    }
                host_data["ports"].append(port_data)
            report_data["hosts"].append(host_data)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            logger.info(f"JSON report successfully exported to '{output_path}'.")
        except OSError as e:
            logger.exception(f"Failed to write JSON report to '{output_path}': {e!s}")
            raise
