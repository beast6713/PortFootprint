"""
DnsFingerprinter sending valid DNS TCP queries and verifying response ID fields.
"""

import socket
from typing import Any

from portfootprint.core.models import ServiceMetadata
from portfootprint.services.protocols.base import BaseFingerprintModule
from portfootprint.services.registry import registry


@registry.register(ports=[53], keywords=["dns", "bind", "powerdns", "unbound"], priority=10)
class DnsFingerprinter(BaseFingerprintModule):
    """
    DNS Fingerprinting module.
    Submits a mock TCP DNS query and verifies the response header transaction ID.
    """

    def fingerprint(self, sock: socket.socket, target: str, port: int, timeout: float) -> ServiceMetadata:
        # Standard DNS query for example.com A record over TCP
        # RFC 1035: TCP query is prefixed with 2-byte length
        dns_query = (
            b"\x00\x1d"  # 2-byte Length prefix (29 bytes query)
            b"\x12\x34"  # Transaction ID: 0x1234
            b"\x01\x00"  # Flags: Standard query, recursion desired
            b"\x00\x01"  # Questions count: 1
            b"\x00\x00\x00\x00\x00\x00"  # Answer/Authority/Additional count: 0
            b"\x07example\x03com\x00"  # Query Name: example.com
            b"\x00\x01"  # Type: A record (1)
            b"\x00\x01"  # Class: IN class (1)
        )

        response = self.send_and_recv(sock, dns_query, read_timeout=timeout)

        is_dns = False
        extra: dict[str, Any] = {}

        if len(response) >= 14:  # 2-byte len prefix + 12-byte header minimum
            resp_id = response[2:4]
            # If response transaction ID matches query transaction ID
            if resp_id == b"\x12\x34":
                is_dns = True
                # Extract flags byte to check response flag
                flags = response[4:6]
                is_response = (flags[0] & 0x80) != 0
                extra["dns_response_flag_check"] = is_response
                extra["dns_transaction_id"] = "0x1234"

        service_name = "DNS" if is_dns else "Unknown Service"
        version = "DNS over TCP" if is_dns else ""
        banner = "Standard DNS Resolver" if is_dns else ""

        return ServiceMetadata(
            service_name=service_name, protocol="tcp", version=version, banner=banner, extra_details=extra
        )
