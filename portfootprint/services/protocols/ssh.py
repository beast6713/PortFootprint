"""
SshFingerprinter parsing version strings from SSH greeting banners.
"""

import contextlib
import socket

from portfootprint.core.models import ServiceMetadata
from portfootprint.services.protocols.base import BaseFingerprintModule
from portfootprint.services.registry import registry


@registry.register(ports=[22], keywords=["ssh"], priority=10)
class SshFingerprinter(BaseFingerprintModule):
    """
    SSH Fingerprinting module.
    Parses protocol version and software implementation version from SSH greeting.
    """
    def fingerprint(self, sock: socket.socket, target: str, port: int, timeout: float) -> ServiceMetadata:
        # Passive read or active read can be fetched from the banner grabber,
        # but let's read/verify on the socket directly if we don't have it.
        # Since the banner grabber already grabbed the banner passively (and stored it),
        # we can perform a quick read on the socket, or if it times out, assume the initial banner.

        # Try a quick read first (no probe needed for SSH since it sends passive banner)
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        banner_text = ""

        try:
            # Sockets might already have data in queue buffer
            data = sock.recv(1024)
            banner_text = self.safe_decode(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                sock.settimeout(original_timeout)

        # Parse standard SSH banner pattern: SSH-[protoversion]-[softwareversion]
        # e.g., SSH-2.0-OpenSSH_8.2p1 ubuntu
        if not banner_text or not banner_text.startswith("SSH-"):
            return ServiceMetadata(service_name="Unknown Service")

        protocol_version = "Unknown"
        software_version = "Unknown"

        parts = banner_text.strip().split("-", 2)
        if len(parts) >= 2:
            protocol_version = parts[1]
        software_version = parts[2] if len(parts) >= 3 else "Generic SSH"

        extra = {
            "raw_banner": banner_text,
            "ssh_protocol_version": protocol_version,
            "ssh_software_version": software_version
        }

        # Use software version as service version identifier
        version = software_version

        return ServiceMetadata(
            service_name="SSH",
            protocol="tcp",
            version=version,
            banner=banner_text,
            extra_details=extra
        )
