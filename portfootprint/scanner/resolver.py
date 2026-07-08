"""
Target validation and DNS host resolution for PortFootprint targets.
"""

import re
import socket

from portfootprint.core.exceptions import TargetResolutionError


class TargetResolver:
    """
    Validates host formats and resolves hostnames to active IP addresses.
    Raises TargetResolutionError for resolution or format issues.
    """
    @staticmethod
    def is_valid_ip(address: str) -> bool:
        """Determines if the input is a valid IPv4 or IPv6 address structure."""
        # Check IPv4
        try:
            socket.inet_pton(socket.AF_INET, address)
            return True
        except OSError:
            pass

        # Check IPv6
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except OSError:
            pass

        return False

    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        """Determines if the target string conforms to DNS hostname specs."""
        if not hostname or len(hostname) > 255:
            return False
        # Remove trailing dot if exists
        if hostname[-1] == ".":
            hostname = hostname[:-1]

        # Regex check for label structures
        # Each label is 1-63 chars, containing alphanumeric and hyphens.
        # Cannot start or end with hyphen.
        allowed = re.compile(r"^(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])"
                             r"(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$")
        return bool(allowed.match(hostname))

    def resolve(self, target: str) -> tuple[str, socket.AddressFamily]:
        """
        Resolves hostname to IP address.
        Returns a tuple of (ip_address, address_family).
        """
        # Strip protocols or slashes if user mistakenly typed them
        cleaned_target = target.strip().lower()
        if "://" in cleaned_target:
            cleaned_target = cleaned_target.split("://")[-1]
        cleaned_target = cleaned_target.split("/")[0]
        # Remove port if specified (handling IPv6 brackets or single colon host:port)
        if cleaned_target.startswith("[") and "]" in cleaned_target:
            parts = cleaned_target.split("]")
            cleaned_target = parts[0][1:]
        elif cleaned_target.count(":") == 1:
            cleaned_target = cleaned_target.split(":")[0]

        if not cleaned_target:
            raise TargetResolutionError("Resolved target hostname cannot be empty.")

        # Check if already a valid IP address
        if self.is_valid_ip(cleaned_target):
            # Check family
            if ":" in cleaned_target:
                return cleaned_target, socket.AF_INET6
            return cleaned_target, socket.AF_INET

        # Verify DNS hostname validity structure before lookup
        if not self.is_valid_hostname(cleaned_target):
            raise TargetResolutionError(f"Target format '{target}' is not a valid hostname or IP address.")

        # Perform DNS lookup
        try:
            # Use getaddrinfo to resolve both IPv4/IPv6 address families
            addr_info = socket.getaddrinfo(cleaned_target, None)
            if not addr_info:
                raise TargetResolutionError(f"DNS lookup returned no records for target '{cleaned_target}'.")

            # Prefer IPv4 if available, otherwise use IPv6
            ipv4_candidates = [info for info in addr_info if info[0] == socket.AF_INET]
            if ipv4_candidates:
                ip = str(ipv4_candidates[0][4][0])
                return ip, socket.AF_INET

            # Fallback to IPv6
            ip = str(addr_info[0][4][0])
            return ip, addr_info[0][0]

        except socket.gaierror as e:
            raise TargetResolutionError(
                f"Failed to resolve target hostname '{cleaned_target}': {e.strerror}"
            ) from e
        except Exception as e:
            raise TargetResolutionError(
                f"Unexpected resolution error for target '{cleaned_target}': {e!s}"
            ) from e
