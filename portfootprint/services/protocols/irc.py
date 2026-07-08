"""
IrcFingerprinter parsing notices and commands from IRC welcome ports.
"""

import contextlib
import re
import socket

from portfootprint.core.models import ServiceMetadata
from portfootprint.services.protocols.base import BaseFingerprintModule
from portfootprint.services.registry import registry


@registry.register(ports=[6667, 6697, 6660, 6669], keywords=["irc", "unrealircd", "ircd"], priority=10)
class IrcFingerprinter(BaseFingerprintModule):
    """
    IRC Fingerprinting module.
    Pulls initial auth lines and registers nicknames to verify server versions.
    """
    def fingerprint(self, sock: socket.socket, target: str, port: int, timeout: float) -> ServiceMetadata:
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        banner_text = ""

        # 1. Passive read check (IRC servers usually send welcome notices immediately)
        try:
            data = sock.recv(1024)
            banner_text = self.safe_decode(data)
        except OSError:
            pass

        # 2. Active registration if passive yielded no notice check
        is_irc = "NOTICE AUTH" in banner_text or "PING :" in banner_text

        if not is_irc:
            probe = b"NICK pfscan\r\nUSER pfscan 0 * :pfscan\r\n"
            reg_bytes = self.send_and_recv(sock, probe, read_timeout=timeout)
            reg_text = self.safe_decode(reg_bytes)
            banner_text += f"\n{reg_text}".strip()

            # Check for standard server response identifiers (e.g. NOTICE, PING, or standard reply codes)
            if any(term in reg_text for term in ("NOTICE", "PING", "001", "004", "unrealircd")):
                is_irc = True

        version = "Unknown IRC Server"
        server_name = "Unknown"
        if is_irc:
            # Parse server banner version if present
            # e.g., :irc.example.com 004 pfscan irc.example.com UnrealIRCd-5.2.1
            match = re.search(r"UnrealIRCd-([\w\.]+)", banner_text, re.IGNORECASE)
            if match:
                version = f"UnrealIRCd {match.group(1)}"
            else:
                match_generic = re.search(r"([\w\.\-]+irc[\w\.\-]+)", banner_text, re.IGNORECASE)
                server_name = match_generic.group(1) if match_generic else target
                version = f"IRC Daemon ({server_name})"

        extra = {
            "raw_banner": banner_text,
            "is_irc_confirmed": is_irc,
            "irc_server_name": server_name,
        }

        # Restore original timeout settings
        with contextlib.suppress(OSError):
            sock.settimeout(original_timeout)

        service_name = "IRC" if is_irc else "Unknown Service"
        version_str = version if is_irc else ""
        banner_str = banner_text if is_irc else ""

        return ServiceMetadata(
            service_name=service_name,
            protocol="tcp",
            version=version_str,
            banner=banner_str,
            extra_details=extra
        )
