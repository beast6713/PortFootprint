"""
SmtpFingerprinter sending EHLO and checking mail extensions and STARTTLS capabilities.
"""

import contextlib
import socket

from portfootprint.core.models import ServiceMetadata
from portfootprint.services.protocols.base import BaseFingerprintModule
from portfootprint.services.registry import registry


@registry.register(ports=[25, 587, 465], keywords=["smtp", "postfix", "exim", "sendmail"], priority=10)
class SmtpFingerprinter(BaseFingerprintModule):
    """
    SMTP Fingerprinting module.
    Pulls mail banners, sends EHLO, and parses SMTP extension keywords.
    """
    def fingerprint(self, sock: socket.socket, target: str, port: int, timeout: float) -> ServiceMetadata:
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        banner_text = ""

        try:
            data = sock.recv(1024)
            banner_text = self.safe_decode(data)
        except OSError:
            pass

        # Send EHLO command
        ehlo_bytes = self.send_and_recv(sock, b"EHLO portfootprint\r\n", read_timeout=timeout)
        ehlo_text = self.safe_decode(ehlo_bytes)

        extensions: list[str] = []
        starttls_supported = False

        if ehlo_text:
            lines = ehlo_text.split("\r\n")
            for line in lines:
                line_strip = line.strip()
                # EHLO response lines start with 250
                if line_strip.startswith("250"):
                    # e.g., 250-STARTTLS or 250 STARTTLS -> STARTTLS
                    val = line_strip[4:].strip()
                    if val:
                        extensions.append(val)
                        if "STARTTLS" in val.upper():
                            starttls_supported = True

        extra = {
            "raw_banner": banner_text,
            "ehlo_response": ehlo_text,
            "smtp_extensions": extensions,
            "starttls_support": starttls_supported
        }

        # Restore original timeout settings
        with contextlib.suppress(OSError):
            sock.settimeout(original_timeout)

        return ServiceMetadata(
            service_name="SMTP",
            protocol="tcp",
            version="SMTP Mail Server",
            banner=banner_text,
            extra_details=extra
        )
