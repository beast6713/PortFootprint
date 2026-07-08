"""
Thread-safe ResultAggregator compiling port results into hosts and scan outputs.
"""

import threading
import time

from portfootprint.core.models import HostResult, PortResult, ScanResult


class ResultAggregator:
    """
    Accumulates scanned port results from worker threads.
    Compiles HostResult and ScanResult structures upon completion.
    """
    def __init__(self, target: str, resolved_ip: str, total_ports_count: int) -> None:
        self.target = target
        self.resolved_ip = resolved_ip
        self.total_ports_count = total_ports_count
        self._port_results: list[PortResult] = []
        self._lock = threading.Lock()
        self.start_time = time.time()

    def add_port_result(self, result: PortResult) -> None:
        """Appends a scanned port result thread-safely."""
        with self._lock:
            self._port_results.append(result)

    def get_port_results(self) -> list[PortResult]:
        """Returns a copy of the gathered port results list sorted by port number."""
        with self._lock:
            return sorted(self._port_results, key=lambda x: x.port)

    def compile(self) -> ScanResult:
        """
        Finalizes tracking stats and returns a consolidated ScanResult.
        Calculates total runtime duration.
        """
        end_time = time.time()
        duration = end_time - self.start_time

        # Sort port results for consistent output
        sorted_ports = self.get_port_results()

        host_res = HostResult(
            target=self.target,
            ip_address=self.resolved_ip,
            ports=sorted_ports
        )

        return ScanResult(
            target=self.target,
            resolved_ip=self.resolved_ip,
            total_ports=self.total_ports_count,
            hosts=[host_res],
            start_time=self.start_time,
            end_time=end_time,
            duration=duration
        )
