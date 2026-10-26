"""
ScanStatistics module computing execution performance and discovery metrics.
"""

from collections import Counter
from dataclasses import dataclass

from portfootprint.core.models import ScanResult


@dataclass(frozen=True)
class ScanStatistics:
    """Stores calculated performance and status metrics from a scan run."""

    total_ports: int
    open_count: int
    closed_count: int
    filtered_count: int
    unknown_count: int
    scan_speed: float
    services_detected: int
    most_common_protocol: str

    @classmethod
    def calculate(cls, scan_result: ScanResult) -> "ScanStatistics":
        """Analyzes ScanResult metrics and returns a ScanStatistics instance."""
        total_ports = scan_result.total_ports
        open_count = 0
        closed_count = 0
        filtered_count = 0
        unknown_count = 0
        services_detected = 0

        protocols = []

        if scan_result.hosts:
            host_res = scan_result.hosts[0]
            for port in host_res.ports:
                state = port.state.upper()
                if state == "OPEN":
                    open_count += 1
                    if port.service:
                        services_detected += 1
                        protocols.append(port.service.service_name)
                elif state == "CLOSED":
                    closed_count += 1
                elif state == "FILTERED":
                    filtered_count += 1
                else:
                    unknown_count += 1

        # Calculate scan speed (ports per second)
        duration = scan_result.duration
        scan_speed = 0.0
        if duration > 0.0:
            scan_speed = total_ports / duration

        # Find most common protocol
        most_common_protocol = "None"
        if protocols:
            counter = Counter(protocols)
            most_common_protocol = counter.most_common(1)[0][0]

        return cls(
            total_ports=total_ports,
            open_count=open_count,
            closed_count=closed_count,
            filtered_count=filtered_count,
            unknown_count=unknown_count,
            scan_speed=scan_speed,
            services_detected=services_detected,
            most_common_protocol=most_common_protocol,
        )
