"""
BaseFingerprintModule class defining contracts and common networking helpers.
"""

import contextlib
import logging
import socket
from abc import ABC, abstractmethod

from portfootprint.core.models import ServiceMetadata

logger = logging.getLogger("portfootprint.services.protocols.base")


class BaseFingerprintModule(ABC):
    """
    Abstract interface for all protocol-specific fingerprinting modules.
    Provides utility methods to send requests and decode socket responses.
    """
    @abstractmethod
    def fingerprint(self, sock: socket.socket, target: str, port: int, timeout: float) -> ServiceMetadata:
        """
        Executes connection handshakes and returns populated ServiceMetadata.
        Never closes the passed socket, but may modify timeouts.
        """
        pass

    def safe_decode(self, data: bytes) -> str:
        """Decodes raw byte arrays safely using UTF-8/Latin-1 fallback."""
        if not data:
            return ""
        try:
            return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            try:
                return data.decode("latin-1", errors="ignore").strip()
            except Exception:
                return ""

    def send_and_recv(
        self,
        sock: socket.socket,
        payload: bytes,
        read_timeout: float = 2.0,
        max_bytes: int = 2048
    ) -> bytes:
        """
        Sends payload and attempts to read returned bytes with specified timeout.
        Catches socket errors cleanly and returns gathered bytes.
        """
        original_timeout = sock.gettimeout()
        sock.settimeout(read_timeout)
        response = b""

        try:
            sock.sendall(payload)
            response = sock.recv(max_bytes)
        except socket.timeout:
            logger.debug("Socket read timed out during protocol probe.")
        except OSError as e:
            logger.debug(f"Socket IO error during protocol probe: {e!s}")
        finally:
            with contextlib.suppress(OSError):
                sock.settimeout(original_timeout)

        return response
