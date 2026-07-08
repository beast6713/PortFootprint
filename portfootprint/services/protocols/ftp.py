"""
FtpFingerprinter extracting greetings and FEAT capabilities from FTP welcome ports.
"""

import contextlib
import re
import socket

from portfootprint.core.models import ServiceMetadata
from portfootprint.services.protocols.base import BaseFingerprintModule
from portfootprint.services.registry import registry


@registry.register(ports=[21], keywords=["ftp"], priority=10)
class FtpFingerprinter(BaseFingerprintModule):
    """
    FTP Fingerprinting module.
    Pulls FTP greetings, parses software versions, and queries FEAT extensions.
    """
    def fingerprint(self, sock: socket.socket, target: str, port: int, timeout: float) -> ServiceMetadata:
        # FTP immediately outputs standard 220 banner upon connection
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        banner_text = ""

        try:
            data = sock.recv(1024)
            banner_text = self.safe_decode(data)
        except OSError:
            pass

        # Parse version info from banner (e.g. VSFTPD x.x.x, ProFTPD x.x.x)
        version = "Unknown"
        if banner_text:
            #VSFTPD, ProFTPD, Pure-FTPd etc.
            match = re.search(r"(vsftpd|proftpd|pure-ftpd|war-ftpd|filezilla)[\s/]?([\d\.]+)?", banner_text, re.IGNORECASE)
            if match:
                version = match.group(2) if match.group(2) else match.group(1)

        # Query features (FEAT)
        feat_bytes = self.send_and_recv(sock, b"FEAT\r\n", read_timeout=timeout)
        feat_text = self.safe_decode(feat_bytes)

        # Extract options from FEAT response lines
        capabilities: list[str] = []
        if feat_text:
            for line in feat_text.split("\r\n"):
                line_strip = line.strip()
                # Features are listed indented or after a 211 status
                if line_strip and not any(line_strip.startswith(c) for c in ("211", "530", "500", "502")):
                    capabilities.append(line_strip)

        extra = {
            "raw_banner": banner_text,
            "ftp_features": capabilities,
        }

        # Restore original timeout settings
        with contextlib.suppress(OSError):
            sock.settimeout(original_timeout)

        return ServiceMetadata(
            service_name="FTP",
            protocol="tcp",
            version=version,
            banner=banner_text,
            extra_details=extra
        )
