"""
Unit tests for BannerGrabber, ProtocolRegistry, ServiceDetector, and all fingerprint protocols.
"""

from unittest.mock import MagicMock, patch

from portfootprint.core.models import PortResult
from portfootprint.services.banner import BannerGrabber
from portfootprint.services.detector import ServiceDetector
from portfootprint.services.protocols.database import DatabaseFingerprinter
from portfootprint.services.protocols.dns import DnsFingerprinter
from portfootprint.services.protocols.ftp import FtpFingerprinter
from portfootprint.services.protocols.http import HttpFingerprinter
from portfootprint.services.protocols.https import HttpsFingerprinter
from portfootprint.services.protocols.irc import IrcFingerprinter
from portfootprint.services.protocols.smtp import SmtpFingerprinter
from portfootprint.services.protocols.ssh import SshFingerprinter
from portfootprint.services.registry import registry


def test_banner_grabber_passive() -> None:
    """Verifies that BannerGrabber retrieves passive welcome banners."""
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"220 FTP Server Ready\r\n"

    grabber = BannerGrabber(read_timeout=1.0)
    banner = grabber.grab(mock_socket)

    assert banner == "220 FTP Server Ready"
    mock_socket.recv.assert_called_once()


def test_banner_grabber_active() -> None:
    """Verifies that BannerGrabber falls back to active probes if passive read is empty."""
    mock_socket = MagicMock()
    # First recv returns empty bytes, second recv returns active response
    mock_socket.recv.side_effect = [b"", b"HTTP/1.1 200 OK\r\n"]

    grabber = BannerGrabber(read_timeout=1.0)
    banner = grabber.grab(mock_socket)

    assert banner == "HTTP/1.1 200 OK"
    mock_socket.sendall.assert_called_once_with(b"\r\n\r\n")


def test_protocol_registry_matching() -> None:
    """Verifies that registry returns matching candidate classes based on ports/banners."""
    candidates = registry.get_candidates(port=80, banner="")
    assert HttpFingerprinter in candidates

    candidates_ssh = registry.get_candidates(port=9999, banner="SSH-2.0-OpenSSH")
    assert SshFingerprinter in candidates_ssh


def test_service_detector_fallbacks() -> None:
    """Verifies detector defaults to common port mappings if handshakes fail."""
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b""
    # Mock candidates failing fingerprinting
    detector = ServiceDetector(target="localhost", timeout=1.0)

    port_result = PortResult(port=22, state="OPEN")
    result = detector.detect(port_result, mock_socket, banner="unrecognized banner")

    assert result.service is not None
    assert result.service.service_name == "SSH"
    assert result.service.banner == "unrecognized banner"


def test_http_fingerprinter() -> None:
    """Verifies HTTP headers and page title extraction."""
    mock_socket = MagicMock()
    # Return mock HTTP server response
    mock_socket.recv.return_value = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.41\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head><title>Test Page</title></head></html>"
    )

    fingerprinter = HttpFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=80, timeout=1.0)

    assert meta.service_name == "HTTP"
    assert meta.version == "2.4.41"
    assert meta.banner == "Apache/2.4.41"
    assert meta.title == "Test Page"
    assert meta.headers.get("content-type") == "text/html"


@patch("ssl.create_default_context")
def test_https_fingerprinter(mock_create_context: MagicMock) -> None:
    """Verifies Https wrapping and peer certificate parameter checks."""
    mock_ssl_context = MagicMock()
    mock_ssl_sock = MagicMock()
    mock_create_context.return_value = mock_ssl_context
    mock_ssl_context.wrap_socket.return_value = mock_ssl_sock

    mock_ssl_sock.version.return_value = "TLSv1.3"
    mock_ssl_sock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
    mock_ssl_sock.getpeercert.return_value = {
        "subject": ((("commonName", "localhost"),),),
        "issuer": ((("commonName", "CA Issuer"),),),
        "serialNumber": "12345",
        "notAfter": "Jan 01 2027",
    }

    mock_socket = MagicMock()
    fingerprinter = HttpsFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=443, timeout=1.0)

    assert meta.service_name == "HTTPS"
    assert meta.version == "TLSv1.3"
    assert meta.certificate.get("serial_number") == "12345"
    assert "CA Issuer" in meta.certificate.get("issuer", "")


def test_ssh_fingerprinter() -> None:
    """Verifies parsing of SSH software and protocol versions."""
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"

    fingerprinter = SshFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=22, timeout=1.0)

    assert meta.service_name == "SSH"
    assert meta.version == "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    assert meta.extra_details.get("ssh_protocol_version") == "2.0"


def test_ftp_fingerprinter() -> None:
    """Verifies FTP greeting versions and FEAT features checks."""
    mock_socket = MagicMock()
    # Mock passive banner, then FEAT response
    mock_socket.recv.side_effect = [b"220 vsFTPd 3.0.3 Server\r\n", b"211-Features:\r\n EPRT\r\n EPSV\r\n211 End\r\n"]

    fingerprinter = FtpFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=21, timeout=1.0)

    assert meta.service_name == "FTP"
    assert meta.version == "3.0.3"
    assert "EPRT" in meta.extra_details.get("ftp_features", [])


def test_smtp_fingerprinter() -> None:
    """Verifies SMTP greetings EHLO parsing."""
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [
        b"220 mail.local ESMTP Postfix\r\n",
        b"250-mail.local\r\n250-STARTTLS\r\n250 PIPELINING\r\n",
    ]

    fingerprinter = SmtpFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=25, timeout=1.0)

    assert meta.service_name == "SMTP"
    assert meta.extra_details.get("starttls_support") is True
    assert "STARTTLS" in meta.extra_details.get("smtp_extensions", [])


def test_dns_fingerprinter() -> None:
    """Verifies standard TCP DNS resolver headers responses checks."""
    mock_socket = MagicMock()
    # Return mock DNS response: 2-byte len + 12-byte header.
    # Response ID must match query ID \x12\x34, and have response flag set
    mock_socket.recv.return_value = b"\x00\x0c\x12\x34\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00"

    fingerprinter = DnsFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=53, timeout=1.0)

    assert meta.service_name == "DNS"
    assert meta.version == "DNS over TCP"


def test_irc_fingerprinter() -> None:
    """Verifies IRC NOTICE AUTH detection checks."""
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b":irc.server.net NOTICE AUTH :*** Looking up your hostname...\r\n"

    fingerprinter = IrcFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=6667, timeout=1.0)

    assert meta.service_name == "IRC"
    assert "NOTICE AUTH" in meta.banner


def test_database_fingerprinter_mysql() -> None:
    """Verifies MySQL passive greeting version parsing."""
    mock_socket = MagicMock()
    # MySQL greeting header starts at offset 4 with protocol version 10,
    # followed by null-terminated server version
    mock_socket.recv.return_value = b"\x0a\x00\x00\x00\x0a8.0.25-0ubuntu0.20.04.1\x00"

    fingerprinter = DatabaseFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=3306, timeout=1.0)

    assert meta.service_name == "MySQL"
    assert meta.version == "8.0.25-0ubuntu0.20.04.1"


def test_database_fingerprinter_redis() -> None:
    """Verifies Redis PING-PONG response check."""
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"+PONG\r\n"

    fingerprinter = DatabaseFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=6379, timeout=1.0)

    assert meta.service_name == "Redis"
    assert meta.version == "Redis Key-Value Store"


def test_database_fingerprinter_postgres() -> None:
    """Verifies Postgres SSLRequest and ErrorResponse checks."""
    mock_socket = MagicMock()
    # First recv for SSLRequest, second recv for StartupMessage ErrorResponse
    mock_socket.recv.side_effect = [b"S", b"E\x00\x00\x00\x14SFATAL\x00"]

    fingerprinter = DatabaseFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=5432, timeout=1.0)

    assert meta.service_name == "PostgreSQL"
    assert meta.extra_details.get("ssl_supported") is True
    assert meta.extra_details.get("postgres_verified") is True


def test_database_fingerprinter_mongodb() -> None:
    """Verifies MongoDB OP_REPLY structure checks."""
    mock_socket = MagicMock()
    # Opcode OP_REPLY is 2005 (b"\xd5\x07\x00\x00" at offset 12-16)
    mock_socket.recv.return_value = b"\x20\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd5\x07\x00\x00ismaster\x00"

    fingerprinter = DatabaseFingerprinter()
    meta = fingerprinter.fingerprint(mock_socket, target="localhost", port=27017, timeout=1.0)

    assert meta.service_name == "MongoDB"
    assert meta.extra_details.get("mongodb_is_master_resp") is True
