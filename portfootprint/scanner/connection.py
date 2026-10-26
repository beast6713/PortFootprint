"""
ConnectionHandler managing socket connection attempts, timeouts, and retries.
"""

import errno
import socket
import time

from portfootprint.core.constants import (
    PORT_STATUS_CLOSED,
    PORT_STATUS_FILTERED,
    PORT_STATUS_OPEN,
    PORT_STATUS_UNKNOWN,
)
from portfootprint.core.models import PortResult


class ConnectionHandler:
    """
    Manages low-level socket connections to verify TCP port accessibility.
    Determines port states (OPEN, CLOSED, FILTERED) and implements retries.
    """

    def __init__(self, ip_address: str, address_family: socket.AddressFamily = socket.AF_INET) -> None:
        self.ip_address = ip_address
        self.address_family = address_family

    def scan_port(self, port: int, timeout: float, retries: int) -> PortResult:
        """
        Attempts a TCP connection to the destination port.
        Retries on timeouts/failures if retries > 0.
        Returns a PortResult dataclass.
        """
        attempts = retries + 1
        last_reason = ""
        last_state = PORT_STATUS_UNKNOWN
        start_time = time.time()

        for attempt in range(attempts):
            sock = socket.socket(self.address_family, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            try:
                # connect_ex returns standard errno
                result_code = sock.connect_ex((self.ip_address, port))

                if result_code == 0:
                    sock.close()
                    elapsed = time.time() - start_time
                    return PortResult(
                        port=port, state=PORT_STATUS_OPEN, reason="Connection succeeded", duration=elapsed
                    )

                # Check errno status codes
                if result_code in (errno.ETIMEDOUT, 10060, errno.EHOSTUNREACH, errno.ENETUNREACH):
                    last_state = PORT_STATUS_FILTERED
                    last_reason = f"Connection timeout (errno {result_code})"
                elif result_code in (errno.ECONNREFUSED, 10061):
                    last_state = PORT_STATUS_CLOSED
                    last_reason = f"Connection refused (errno {result_code})"
                else:
                    last_state = PORT_STATUS_CLOSED
                    last_reason = f"Socket error code {result_code}"

            except socket.timeout:
                last_state = PORT_STATUS_FILTERED
                last_reason = "Socket timeout exception"
            except OSError as e:
                # Catch other socket exceptions
                last_state = PORT_STATUS_CLOSED if e.errno in (errno.ECONNREFUSED, 10061) else PORT_STATUS_FILTERED
                last_reason = str(e)
            finally:
                sock.close()

            # Optional tiny pause between retries to avoid flooding
            if attempt < attempts - 1:
                time.sleep(0.01)

        elapsed = time.time() - start_time
        return PortResult(port=port, state=last_state, reason=last_reason, duration=elapsed)
