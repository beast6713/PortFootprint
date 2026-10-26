"""
HttpsFingerprinter wrapping sockets with TLS and extracting certificate fields.
"""

import contextlib
import logging
import socket
import ssl
from typing import Any

from portfootprint.core.models import ServiceMetadata
from portfootprint.services.protocols.base import BaseFingerprintModule
from portfootprint.services.registry import registry

logger = logging.getLogger("portfootprint.services.protocols.https")


@registry.register(ports=[443, 8443], keywords=["https", "ssl", "tls"], priority=15)
class HttpsFingerprinter(BaseFingerprintModule):
    """
    HTTPS/TLS Fingerprinting module.
    Wraps standard TCP socket into SSL wrapper and parses certificate fields.
    """

    def _format_cert_name(self, name_tuples: Any) -> str:
        if not name_tuples:
            return ""
        parts = []
        try:
            for rdns in name_tuples:
                for attr, value in rdns:
                    parts.append(f"{attr}={value}")
        except Exception:
            return str(name_tuples)
        return ", ".join(parts)

    def _is_self_signed(self, subject: str, issuer: str) -> bool:
        if not subject or not issuer:
            return False
        # Simple string equality comparison
        return subject == issuer

    def fingerprint(self, sock: socket.socket, target: str, port: int, timeout: float) -> ServiceMetadata:
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)

        # Configure SSL context to bypass validation and avoid blocking scans
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        cert_details: dict[str, Any] = {}
        tls_version = "Unknown"
        cipher_suite = "Unknown"

        try:
            ssl_sock = context.wrap_socket(sock, server_hostname=target)

            # Extract TLS metrics
            tls_version = ssl_sock.version() or "Unknown"
            cipher_info = ssl_sock.cipher()
            cipher_suite = cipher_info[0] if cipher_info else "Unknown"

            # Get binary cert information
            peercert = ssl_sock.getpeercert()
            if peercert:
                subject_str = self._format_cert_name(peercert.get("subject"))
                issuer_str = self._format_cert_name(peercert.get("issuer"))

                cert_details = {
                    "subject": subject_str,
                    "issuer": issuer_str,
                    "version": peercert.get("version", ""),
                    "serial_number": peercert.get("serialNumber", ""),
                    "not_before": peercert.get("notBefore", ""),
                    "not_after": peercert.get("notAfter", ""),
                    "san": str(peercert.get("subjectAltName", "")),
                    "self_signed": self._is_self_signed(subject_str, issuer_str),
                }

            # Close SSL layer but keep basic socket open (since caller manages socket cleanup)
            # Actually, standard wrap_socket close policies might close raw socket,
            # so we let the worker manage socket closure anyway.
        except Exception as e:
            logger.debug(f"SSL handshake failed on {target}:{port} - {e!s}")
            cert_details = {"handshake_error": str(e)}

        # Format version output
        version = tls_version
        banner = f"TLS HTTPS ({tls_version}, {cipher_suite})"

        # Put everything into extra details
        extra = {
            "tls_version": tls_version,
            "cipher": cipher_suite,
        }
        if cert_details:
            extra.update(cert_details)

        # Restore original timeout settings
        with contextlib.suppress(OSError):
            sock.settimeout(original_timeout)

        return ServiceMetadata(
            service_name="HTTPS",
            protocol="tcp",
            version=version,
            banner=banner,
            certificate=cert_details,
            extra_details=extra,
        )
