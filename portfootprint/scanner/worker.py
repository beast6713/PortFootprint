"""
ScanWorker pulling tasks, executing ConnectionHandler, and registering results.
"""

import contextlib
import logging
import socket

from portfootprint.core.models import PortResult
from portfootprint.core.progress import ProgressTracker
from portfootprint.core.result_aggregator import ResultAggregator
from portfootprint.scanner.connection import ConnectionHandler

logger = logging.getLogger("portfootprint.scanner.worker")


class ScanWorker:
    """
    Executes a single port scan task.
    Updates the progress tracker and registers output with the aggregator.
    """
    def __init__(
        self,
        connection_handler: ConnectionHandler,
        progress_tracker: ProgressTracker,
        result_aggregator: ResultAggregator,
        timeout: float,
        retries: int,
        verbose: bool = False
    ) -> None:
        self.connection_handler = connection_handler
        self.progress_tracker = progress_tracker
        self.result_aggregator = result_aggregator
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose

    def execute(self, port: int) -> PortResult:
        """
        Runs connection check on the target port.
        Pushes results to aggregator and updates progress.
        """
        self.progress_tracker.start_task()
        if self.verbose:
            logger.debug(f"Starting connection scan on port {port}...")

        try:
            result = self.connection_handler.scan_port(
                port=port,
                timeout=self.timeout,
                retries=self.retries
            )

            # Phase 2: If port is OPEN, run service discovery handshakes
            if result.state == "OPEN":
                try:
                    family = self.connection_handler.address_family
                    ip = self.connection_handler.ip_address

                    # Establish a fresh connection socket for protocol probes
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((ip, port))

                    from portfootprint.services.banner import BannerGrabber
                    from portfootprint.services.detector import ServiceDetector

                    # Passive/Active Grab
                    grabber = BannerGrabber(read_timeout=self.timeout)
                    banner = grabber.grab(sock)

                    # Run target identification detector
                    detector = ServiceDetector(
                        target=self.result_aggregator.target,
                        timeout=self.timeout
                    )
                    result = detector.detect(result, sock, banner)
                except Exception as e:
                    logger.debug(f"Service detection connection failed on port {port}: {e!s}")
                finally:
                    with contextlib.suppress(Exception):
                        sock.close()

            # Record result
            self.result_aggregator.add_port_result(result)

            if self.verbose:
                logger.debug(f"Finished scan on port {port}. Result: {result.state}")
            elif result.state == "OPEN":
                logger.info(f"Port {port}/tcp is {result.state}")

            return result
        except Exception as e:
            logger.exception(f"Unexpected error scanning port {port}: {e!s}")
            # Return unknown error result
            fallback = PortResult(
                port=port,
                state="UNKNOWN",
                reason=f"Scan error: {e!s}"
            )
            self.result_aggregator.add_port_result(fallback)
            return fallback
        finally:
            self.progress_tracker.complete_task()
