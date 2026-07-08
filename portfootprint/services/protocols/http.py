"""
HttpFingerprinter sending HEAD/GET probes and parsing response headers and titles.
"""

import re
import socket

from portfootprint.core.models import ServiceMetadata
from portfootprint.services.protocols.base import BaseFingerprintModule
from portfootprint.services.registry import registry


@registry.register(ports=[80, 8080, 8000, 8888], keywords=["http", "html", "nginx", "apache", "iis", "jetty"], priority=10)
class HttpFingerprinter(BaseFingerprintModule):
    """
    HTTP Fingerprinting module.
    Pulls headers, redirection paths, server tags, and page titles.
    """
    def _parse_headers(self, response_text: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        # Find header block before double CRLF
        parts = response_text.split("\r\n\r\n", 1)
        header_lines = parts[0].split("\r\n")

        # Skip status line (first line)
        for line in header_lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()
        return headers

    def _parse_status_code(self, response_text: str) -> str:
        first_line = response_text.split("\r\n", 1)[0]
        match = re.search(r"HTTP/\d\.\d\s+(\d+)", first_line)
        return match.group(1) if match else ""

    def _parse_title(self, response_text: str) -> str:
        match = re.search(r"<title>(.*?)</title>", response_text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return ""

    def fingerprint(self, sock: socket.socket, target: str, port: int, timeout: float) -> ServiceMetadata:
        # Build request probes
        host_header = f"{target}:{port}" if port != 80 else target

        head_probe = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: PortFootprint/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        get_probe = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: PortFootprint/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        # 1. Try HEAD request first
        response_bytes = self.send_and_recv(sock, head_probe, read_timeout=timeout)
        response_text = self.safe_decode(response_bytes)
        status_code = self._parse_status_code(response_text)

        # 2. If status code looks invalid or empty (or 405/400 Method Not Allowed), retry with GET
        if not status_code or status_code in ("400", "405"):
            # Reconnect or retry GET on same socket if close-policy hasn't closed it
            # Standard protocols recommend GET for complete index page title extraction anyway
            response_bytes = self.send_and_recv(sock, get_probe, read_timeout=timeout)
            response_text = self.safe_decode(response_bytes)
            status_code = self._parse_status_code(response_text)

        headers = self._parse_headers(response_text)
        server = headers.get("server", "")
        content_type = headers.get("content-type", "")
        redirect = headers.get("location", "")
        powered_by = headers.get("x-powered-by", "")
        title = self._parse_title(response_text)

        # Compile version from server tag if possible
        version = ""
        if server:
            # e.g., Apache/2.4.41 -> 2.4.41
            match = re.search(r"/([\d\.]+)", server)
            version = match.group(1) if match else server

        extra = {
            "status_code": status_code,
            "content_type": content_type,
            "powered_by": powered_by,
        }
        if redirect:
            extra["redirect"] = redirect

        return ServiceMetadata(
            service_name="HTTP",
            protocol="tcp",
            version=version,
            banner=server,
            headers=headers,
            title=title,
            extra_details=extra
        )
