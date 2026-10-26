"""
BannerGrabber logic checking for passive greetings and sending active probes.
"""

import contextlib
import logging
import socket

logger = logging.getLogger("portfootprint.services.banner")


class BannerGrabber:
    """
    Grabs network service banners passively and actively.
    Decodes received bytes safely using UTF-8/Latin-1 fallback protocols.
    """

    def __init__(self, read_timeout: float = 2.0) -> None:
        self.read_timeout = read_timeout

    def safe_decode(self, data: bytes) -> str:
        """Decodes bytes safely without raising Unicode exceptions."""
        if not data:
            return ""
        try:
            # UTF-8 with ignore strategy is highly robust
            return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            try:
                return data.decode("latin-1", errors="ignore").strip()
            except Exception:
                return ""

    def grab(self, sock: socket.socket) -> str:
        """
        Retrieves welcome banner from socket connection.
        If passive read returns empty/times out, sends a generic ASCII probe.
        """
        original_timeout = sock.gettimeout()
        sock.settimeout(self.read_timeout)
        banner_bytes = b""

        # 1. Passive Grab
        try:
            banner_bytes = sock.recv(1024)
        except socket.timeout:
            logger.debug("Passive banner grab timed out. Transitioning to active probe.")
        except OSError as e:
            logger.debug(f"Passive banner grab socket error: {e!s}")

        # 2. Active Grab (if passive returned nothing)
        if not banner_bytes:
            try:
                # Send standard carriage-return probe
                sock.sendall(b"\r\n\r\n")
                banner_bytes = sock.recv(1024)
            except socket.timeout:
                logger.debug("Active banner grab timed out.")
            except OSError as e:
                logger.debug(f"Active banner grab socket error: {e!s}")

        # Restore original timeout settings
        with contextlib.suppress(OSError):
            sock.settimeout(original_timeout)

        return self.safe_decode(banner_bytes)
