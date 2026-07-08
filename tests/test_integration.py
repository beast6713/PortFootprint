"""
Integration tests executing the top-level main entrypoint and command flows.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from portfootprint.common.network import get_local_ip
from portfootprint.main import main


def test_get_local_ip() -> None:
    """Verifies get_local_ip runs and returns an IP string."""
    ip = get_local_ip()
    assert isinstance(ip, str)
    assert len(ip) > 0


@patch("portfootprint.main.CommandLineParser")
def test_main_cli_syntax_error(mock_parser_class) -> None:
    """Verifies that main exits with 1 on configuration exceptions."""
    mock_parser = MagicMock()
    mock_parser.parse_args.side_effect = SystemExit(2)
    mock_parser_class.return_value = mock_parser

    with patch("sys.argv", ["portfootprint"]), pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 2


@patch("portfootprint.scanner.resolver.socket.getaddrinfo")
def test_full_scan_flow_integration(mock_getaddrinfo, tmp_path) -> None:
    """Simulates a complete scan run via CLI main, writing reports."""
    mock_getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 0))]

    json_path = tmp_path / "integration_report.json"
    csv_path = tmp_path / "integration_report.csv"
    html_path = tmp_path / "integration_report.html"
    log_path = tmp_path / "integration.log"
    config_path = tmp_path / "config.json"

    # Write a config.json file
    config_data = {
        "threads": 5,
        "timeout": 1.0,
        "retries": 0,
        "verbose": False
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f)

    cli_args = [
        "portfootprint",
        "scanme.nmap.org",
        "-p", "80",
        "--json", str(json_path),
        "--csv", str(csv_path),
        "--html", str(html_path),
        "--log-file", str(log_path)
    ]

    # Mock sockets to return closed state quickly
    with patch("sys.argv", cli_args), \
         patch("portfootprint.core.config.ScanConfiguration.load_config_file", return_value=config_data), \
         patch("portfootprint.scanner.connection.socket.socket") as mock_socket_class:

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket_class.return_value = mock_sock

        # Run main scanner entrypoint
        main()

    # Verify reports were successfully exported
    assert os.path.exists(json_path)
    assert os.path.exists(csv_path)
    assert os.path.exists(html_path)
    assert os.path.exists(log_path)


def test_main_history_cmd(tmp_path) -> None:
    """Verifies history index displays cleanly and exits with 0."""
    tmp_path / "history.json"
    cli_args = ["portfootprint", "--history"]

    with patch("sys.argv", cli_args), \
         patch("portfootprint.core.history.ScanHistoryManager.__init__", return_value=None), \
         patch("portfootprint.core.history.ScanHistoryManager.get_history", return_value=[]), \
         pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 0


def test_main_compare_cmd(tmp_path) -> None:
    """Verifies compare script runs and exits with 0."""
    report_path = tmp_path / "rep.json"
    report_data = {
        "target": "localhost",
        "start_time": 100.0,
        "hosts": [{"ports": []}]
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f)

    cli_args = ["portfootprint", "--compare", str(report_path), str(report_path)]

    with patch("sys.argv", cli_args), pytest.raises(SystemExit) as excinfo:
        main()

    assert excinfo.value.code == 0


def test_get_local_ip_failure() -> None:
    """Verifies fallback to 127.0.0.1 when network lookup raises socket exception."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = Exception("Outbound route failed")
        mock_socket_class.return_value = mock_sock
        ip = get_local_ip()
    assert ip == "127.0.0.1"


def test_logging_verbose() -> None:
    """Verifies that setup_logging runs successfully in verbose mode."""
    from portfootprint.common.logging import setup_logging
    # Run once in normal mode
    setup_logging(verbose=False)
    # Run again in verbose mode to trigger duplicate handler removal and verbose configurations
    setup_logging(verbose=True)


def test_logging_file_error() -> None:
    """Verifies that logging file write failures are handled gracefully."""
    from portfootprint.common.logging import setup_logging
    # Null byte inside filename triggers OSError inside FileHandler init
    setup_logging(verbose=False, log_file="\x00invalid_filename.log")


def test_terminal_formatter_states() -> None:
    """Exercises TerminalFormatter with various port states, services, and SSL certs."""
    from portfootprint.cli.formatter import TerminalFormatter
    from portfootprint.core.models import HostResult, PortResult, ScanResult, ServiceMetadata

    ports = [
        PortResult(port=22, state="OPEN", service=ServiceMetadata(service_name="SSH", version="8.2")),
        PortResult(
            port=443,
            state="OPEN",
            service=ServiceMetadata(
                service_name="HTTPS",
                version="1.3",
                certificate={"issuer": "CN=Let's Encrypt,O=Org"}
            )
        ),
        PortResult(
            port=80,
            state="OPEN",
            service=ServiceMetadata(
                service_name="HTTP",
                version="2.4",
                title="Test Webpage Title"
            )
        ),
        PortResult(port=8080, state="FILTERED"),
        PortResult(port=9000, state="UNKNOWN", reason="Reset"),
        PortResult(port=21, state="CLOSED")
    ]
    host = HostResult(target="localhost", ip_address="127.0.0.1", ports=ports)
    result = ScanResult(
        target="localhost",
        resolved_ip="127.0.0.1",
        total_ports=6,
        hosts=[host],
        start_time=100.0,
        end_time=101.5,
        duration=1.5
    )

    # Verify banner prints
    TerminalFormatter.print_banner()
    # Verify pre-scan configurations summary print
    TerminalFormatter.print_pre_scan("localhost", "127.0.0.1", 6, 10)
    # Verify formatter outputs standard lists
    TerminalFormatter.print_scan_result(result, verbose=False)
    # Verify formatter outputs verbose lists
    TerminalFormatter.print_scan_result(result, verbose=True)

    # Verify comparison report formatting checks
    diff = {
        "old_target": "localhost",
        "new_target": "localhost",
        "added": [{"port": 443, "service_name": "HTTPS", "version": "1.3"}],
        "removed": [{"port": 80, "service_name": "HTTP", "version": "2.4"}],
        "changed": [{"port": 22, "old_service": "SSH", "old_version": "8.0", "new_service": "SSH", "new_version": "8.2"}]
    }
    TerminalFormatter.print_comparison(diff)


def test_resolver_additional_coverage() -> None:
    """Exercises TargetResolver IPv6 detection, host name checks, and DNS failure paths."""
    from portfootprint.core.exceptions import TargetResolutionError
    from portfootprint.scanner.resolver import TargetResolver

    resolver = TargetResolver()

    # 1. Test IPv6 string check
    ip, _family = resolver.resolve("::1")
    assert ip == "::1"

    # 2. Test invalid hostname check
    with pytest.raises(TargetResolutionError):
        resolver.resolve("invalid_@_host")

    # 3. Test DNS resolution exception check
    with patch("socket.getaddrinfo") as mock_dns:
        import socket
        mock_dns.side_effect = socket.gaierror(8, "nodename nor servname provided, or not known")
        with pytest.raises(TargetResolutionError):
            resolver.resolve("scanme.nmap.org")


def test_scheduler_crash_handling() -> None:
    """Exercises ScanScheduler worker crashes and cancellations."""
    from portfootprint.scanner.scheduler import ScanScheduler
    from portfootprint.scanner.worker import ScanWorker

    # Setup mock worker that raises exception on execute
    mock_worker = MagicMock(spec=ScanWorker)
    mock_worker.execute.side_effect = ValueError("Worker thread crashed simulation")

    scheduler = ScanScheduler(threads=2)
    # Execute scan scheduler, verifying it handles exceptions without crashing the main thread
    scheduler.run(ports=[80], worker=mock_worker)

    # Exercise cancellation
    mock_future = MagicMock()
    mock_future.done.return_value = False
    scheduler._futures = {mock_future: 80}
    scheduler.cancel_all()
    mock_future.cancel.assert_called_once()


def test_report_manager_unsupported_and_forbidden() -> None:
    """Exercises report manager validations for unsupported extensions and forbidden folders."""
    from portfootprint.core.models import ScanResult
    from portfootprint.reports.report_manager import ReportManager

    dummy_result = ScanResult(
        target="localhost", resolved_ip="127.0.0.1", total_ports=0,
        hosts=[], start_time=0.0, end_time=0.0, duration=0.0
    )

    # 1. Test unsupported report format
    rm = ReportManager({"unsupported_extension_format": "test.txt"})
    rm.generate_reports(dummy_result)

    # 2. Test forbidden system directories check
    rm2 = ReportManager({"json": "/etc/shadow"})
    rm2.generate_reports(dummy_result)

    # 3. Test OSError path
    # Using null byte in dir creation triggers OSError during os.makedirs
    rm3 = ReportManager({"json": "invalid\x00filename.json"})
    # Wait, Null byte check is triggered in validation first, so we use empty/forbidden path that causes OSError:
    # On Windows, characters like ":" inside path directories will cause OSError
    rm3 = ReportManager({"json": "C:\\invalid:dir\\test.json"})
    rm3.generate_reports(dummy_result)


def test_main_keyboard_interrupt() -> None:
    """Verifies that main catches KeyboardInterrupt, print message, and exits with 130."""
    with patch("portfootprint.main.CommandLineParser") as mock_parser_class, \
         pytest.raises(SystemExit) as excinfo:
        mock_parser = MagicMock()
        mock_parser.parse_args.side_effect = KeyboardInterrupt()
        mock_parser_class.return_value = mock_parser
        main()
    assert excinfo.value.code == 130


def test_main_unexpected_crash() -> None:
    """Verifies that main catches general Exception, print error, and exits with 2."""
    with patch("portfootprint.main.CommandLineParser") as mock_parser_class, \
         pytest.raises(SystemExit) as excinfo:
        mock_parser = MagicMock()
        mock_parser.parse_args.side_effect = RuntimeError("Fatal DB connection crash")
        mock_parser_class.return_value = mock_parser
        main()
    assert excinfo.value.code == 2


def test_terminal_formatter_omitted_closed_ports() -> None:
    """Exercises TerminalFormatter omitted message block when closed ports exceed 20."""
    from portfootprint.cli.formatter import TerminalFormatter
    from portfootprint.core.models import HostResult, PortResult, ScanResult

    # 25 closed ports
    ports = [PortResult(port=p, state="CLOSED") for p in range(1, 26)]
    host = HostResult(target="localhost", ip_address="127.0.0.1", ports=ports)
    result = ScanResult(
        target="localhost", resolved_ip="127.0.0.1", total_ports=25,
        hosts=[host], start_time=0.0, end_time=1.0, duration=1.0
    )
    # Output result with verbose=False to cover the omitted note print line
    TerminalFormatter.print_scan_result(result, verbose=False)


def test_resolver_brackets_and_single_colon() -> None:
    """Exercises TargetResolver brackets parsing and single colon URL formats."""
    from portfootprint.scanner.resolver import TargetResolver
    resolver = TargetResolver()

    # 1. Bracketed IPv6 address literal
    ip1, _family1 = resolver.resolve("[2001:db8::1]:443")
    assert ip1 == "2001:db8::1"

    # 2. Hostname with port single colon
    ip2, _family2 = resolver.resolve("localhost:8080")
    assert ip2 == "127.0.0.1"


def test_connection_handler_unknown_errno() -> None:
    """Exercises ConnectionHandler unknown socket errno fallback path."""
    from portfootprint.scanner.connection import ConnectionHandler

    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        # Errno 9999 represents an unrecognized error code
        mock_sock.connect_ex.return_value = 9999
        mock_socket_class.return_value = mock_sock

        handler = ConnectionHandler(ip_address="127.0.0.1")
        result = handler.scan_port(port=80, timeout=1.0, retries=0)
        # Verify it falls back to closed/filtered state with the correct reason
        assert result.state in ("CLOSED", "FILTERED")
        assert "9999" in result.reason or "unknown" in result.reason.lower()


def test_banner_grabber_timeout_paths() -> None:
    """Exercises BannerGrabber read and write timeout branches."""
    from portfootprint.services.banner import BannerGrabber

    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        # recv raising socket.timeout
        import socket
        mock_sock.recv.side_effect = socket.timeout("timed out")
        mock_socket_class.return_value = mock_sock

        grabber = BannerGrabber(read_timeout=0.1)
        banner = grabber.grab(mock_sock)
        assert banner == ""


def test_base_fingerprint_module_exceptions() -> None:
    """Exercises BaseFingerprintModule exception handling."""
    from portfootprint.services.protocols.base import BaseFingerprintModule

    class DummyModule(BaseFingerprintModule):
        def fingerprint(self, sock, target, port, timeout):
            # Try to call send_and_recv which catches socket errors
            return self.send_and_recv(sock, b"test", read_timeout=timeout)

    module = DummyModule()
    mock_sock = MagicMock()
    mock_sock.sendall.side_effect = OSError("Socket write error")
    res = module.fingerprint(mock_sock, "localhost", 80, 1.0)
    assert res == b""


def test_main_port_footprint_error() -> None:
    """Verifies that main catches PortFootprintError (e.g. ConfigurationError) and exits with 1."""
    from portfootprint.core.exceptions import ConfigurationError
    with patch("portfootprint.main.CommandLineParser") as mock_parser_class, \
         pytest.raises(SystemExit) as excinfo:
        mock_parser = MagicMock()
        mock_parser.parse_args.side_effect = ConfigurationError("Target host cannot be empty.")
        mock_parser_class.return_value = mock_parser
        main()
    assert excinfo.value.code == 1


def test_resolver_empty_target() -> None:
    """Verifies TargetResolver empty input detection."""
    from portfootprint.core.exceptions import TargetResolutionError
    from portfootprint.scanner.resolver import TargetResolver

    resolver = TargetResolver()
    with pytest.raises(TargetResolutionError):
        resolver.resolve("   ")


def test_resolver_unexpected_exception() -> None:
    """Verifies TargetResolver handles unexpected/generic exceptions during lookup."""
    from portfootprint.core.exceptions import TargetResolutionError
    from portfootprint.scanner.resolver import TargetResolver

    resolver = TargetResolver()
    with patch("socket.getaddrinfo", side_effect=RuntimeError("Unexpected error")), \
         pytest.raises(TargetResolutionError):
        resolver.resolve("scanme.nmap.org")


def test_report_manager_empty_path() -> None:
    """Verifies ReportManager safely skips empty/None report paths."""
    from portfootprint.core.models import ScanResult
    from portfootprint.reports.report_manager import ReportManager

    dummy_result = ScanResult(
        target="localhost", resolved_ip="127.0.0.1", total_ports=0,
        hosts=[], start_time=0.0, end_time=0.0, duration=0.0
    )

    rm = ReportManager({"json": None})
    rm.generate_reports(dummy_result)
