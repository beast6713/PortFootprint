"""
ServiceDetector coordination engine querying registry and triggering fingerprinters.
"""

import logging
import socket

from portfootprint.core.models import PortResult, ServiceMetadata
from portfootprint.services.registry import registry

# Explicitly import protocols package to trigger decorator registry executions

logger = logging.getLogger("portfootprint.services.detector")


class ServiceDetector:
    """
    Coordinates service identification for verified open ports.
    Dispatches open sockets to matching registry fingerprinters.
    """

    def __init__(self, target: str, timeout: float) -> None:
        self.target = target
        self.timeout = timeout

    def _get_fallback_service_name(self, port: int) -> str:
        """Simple fallback mapping for common ports if handshakes yield no candidates."""
        mapping = {
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTP",
            587: "SMTP",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            6667: "IRC",
            8080: "HTTP",
            27017: "MongoDB",
        }
        return mapping.get(port, "Unknown Service")

    def detect(self, port_result: PortResult, sock: socket.socket, banner: str) -> PortResult:
        """
        Queries the registry for candidate protocols based on port and banner.
        Runs handshakes sequentially and returns an updated PortResult.
        """
        port = port_result.port
        candidates = registry.get_candidates(port, banner)
        service_metadata = None

        # Try matching candidate fingerprinters
        for cls in candidates:
            try:
                fingerprinter = cls()
                logger.debug(f"Attempting fingerprint on port {port} using {cls.__name__}...")
                metadata = fingerprinter.fingerprint(sock=sock, target=self.target, port=port, timeout=self.timeout)

                # Check if it successfully identified a service (not unknown fallback)
                if metadata and metadata.service_name != "Unknown Service":
                    service_metadata = metadata
                    break
            except Exception as e:
                logger.debug(f"Fingerprinter {cls.__name__} failed on port {port}: {e!s}")

        # Fallback if no fingerprinter yielded positive results
        if not service_metadata:
            fallback_name = self._get_fallback_service_name(port)
            service_metadata = ServiceMetadata(service_name=fallback_name, protocol="tcp", version="", banner=banner)

        # Return updated PortResult
        return PortResult(
            port=port_result.port,
            state=port_result.state,
            reason=port_result.reason,
            duration=port_result.duration,
            service=service_metadata,
        )
