"""
Unit tests for ConnectionHandler, ScanWorker, and ScanScheduler with socket mocking.
"""

import socket
from unittest.mock import MagicMock, patch

from portfootprint.core.constants import (
    PORT_STATUS_CLOSED,
    PORT_STATUS_FILTERED,
    PORT_STATUS_OPEN,
)
from portfootprint.core.progress import ProgressTracker
from portfootprint.core.result_aggregator import ResultAggregator
from portfootprint.scanner.connection import ConnectionHandler
from portfootprint.scanner.scheduler import ScanScheduler
from portfootprint.scanner.worker import ScanWorker


@patch("socket.socket")
def test_connection_handler_open_port(mock_socket_class: MagicMock) -> None:
    """Verifies that an open connection returns an OPEN port state."""
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket

    # connect_ex returns 0 for successful connection
    mock_socket.connect_ex.return_value = 0

    handler = ConnectionHandler(ip_address="127.0.0.1")
    result = handler.scan_port(port=80, timeout=1.0, retries=0)

    assert result.port == 80
    assert result.state == PORT_STATUS_OPEN
    mock_socket.connect_ex.assert_called_once_with(("127.0.0.1", 80))


@patch("socket.socket")
def test_connection_handler_closed_port(mock_socket_class: MagicMock) -> None:
    """Verifies that connection refusal returns a CLOSED port state."""
    import errno

    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket

    # Use cross-platform ECONNREFUSED errno status
    mock_socket.connect_ex.return_value = errno.ECONNREFUSED

    handler = ConnectionHandler(ip_address="127.0.0.1")
    result = handler.scan_port(port=80, timeout=1.0, retries=0)

    assert result.port == 80
    assert result.state == PORT_STATUS_CLOSED


@patch("socket.socket")
def test_connection_handler_filtered_port(mock_socket_class: MagicMock) -> None:
    """Verifies that socket timeouts yield FILTERED port state."""
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket

    # Simulate a timeout exception
    mock_socket.connect_ex.side_effect = socket.timeout("timed out")

    handler = ConnectionHandler(ip_address="127.0.0.1")
    result = handler.scan_port(port=80, timeout=1.0, retries=0)

    assert result.port == 80
    assert result.state == PORT_STATUS_FILTERED


def test_scan_worker_execution() -> None:
    """Verifies that the ScanWorker correctly processes a port scan."""
    mock_handler = MagicMock()
    mock_handler.scan_port.return_value = MagicMock(port=80, state=PORT_STATUS_OPEN)

    progress = ProgressTracker(total_tasks=1)
    agg = ResultAggregator(target="localhost", resolved_ip="127.0.0.1", total_ports_count=1)

    worker = ScanWorker(
        connection_handler=mock_handler, progress_tracker=progress, result_aggregator=agg, timeout=1.0, retries=0
    )

    result = worker.execute(80)

    assert result.port == 80
    assert result.state == PORT_STATUS_OPEN
    assert progress.completed_tasks == 1
    assert len(agg.get_port_results()) == 1


def test_scan_scheduler_run() -> None:
    """Verifies that the ScanScheduler correctly manages ThreadPoolExecutor and submits jobs."""
    mock_worker = MagicMock()
    mock_worker.execute.return_value = MagicMock(port=80, state="OPEN")

    scheduler = ScanScheduler(threads=2)
    scheduler.run(ports=[80, 443], worker=mock_worker)

    assert mock_worker.execute.call_count == 2
    mock_worker.execute.assert_any_call(80)
    mock_worker.execute.assert_any_call(443)


@patch("socket.socket")
def test_connection_handler_timeout_errno(mock_socket_class: MagicMock) -> None:
    """Verifies that ETIMEDOUT errno returns a FILTERED port state."""
    import errno

    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket
    mock_socket.connect_ex.return_value = errno.ETIMEDOUT

    handler = ConnectionHandler(ip_address="127.0.0.1")
    result = handler.scan_port(port=80, timeout=1.0, retries=0)

    assert result.state == PORT_STATUS_FILTERED


@patch("socket.socket")
def test_connection_handler_os_error(mock_socket_class: MagicMock) -> None:
    """Verifies that generic socket OSError returns a CLOSED port state."""
    import errno

    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket
    # Raise custom OSError
    mock_socket.connect_ex.side_effect = OSError(errno.ECONNREFUSED, "Refused")

    handler = ConnectionHandler(ip_address="127.0.0.1")
    result = handler.scan_port(port=80, timeout=1.0, retries=0)

    assert result.state == PORT_STATUS_CLOSED


@patch("socket.socket")
def test_connection_handler_retries(mock_socket_class: MagicMock) -> None:
    """Verifies retries triggers sleep logic and reconnect attempts."""
    import errno

    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket
    # Fail both attempts
    mock_socket.connect_ex.return_value = errno.ECONNREFUSED

    handler = ConnectionHandler(ip_address="127.0.0.1")
    # Scan with 1 retry (total 2 attempts)
    result = handler.scan_port(port=80, timeout=1.0, retries=1)

    assert result.state == PORT_STATUS_CLOSED
    assert mock_socket.connect_ex.call_count == 2


def test_scan_worker_service_detection_exception() -> None:
    """Verifies that ScanWorker handles service detection exceptions gracefully."""
    from portfootprint.core.models import PortResult
    from portfootprint.core.progress import ProgressTracker
    from portfootprint.core.result_aggregator import ResultAggregator
    from portfootprint.scanner.connection import ConnectionHandler
    from portfootprint.scanner.worker import ScanWorker

    mock_handler = MagicMock(spec=ConnectionHandler)
    mock_handler.address_family = socket.AF_INET
    mock_handler.ip_address = "127.0.0.1"
    # Return open port status
    mock_handler.scan_port.return_value = PortResult(port=80, state="OPEN")

    progress = ProgressTracker(total_tasks=1)
    agg = ResultAggregator(target="localhost", resolved_ip="127.0.0.1", total_ports_count=1)

    worker = ScanWorker(
        connection_handler=mock_handler, progress_tracker=progress, result_aggregator=agg, timeout=1.0, retries=0
    )

    # Mock socket to raise OSError during socket instantiation inside execute
    with patch("socket.socket", side_effect=OSError("Instantiation failed")):
        result = worker.execute(80)

    assert result.port == 80
    assert result.state == "OPEN"  # Keeps open state even if fingerprinting fails


def test_scan_worker_unexpected_exception() -> None:
    """Verifies that ScanWorker handles generic execute exceptions and returns fallback result."""
    from portfootprint.core.progress import ProgressTracker
    from portfootprint.core.result_aggregator import ResultAggregator
    from portfootprint.scanner.connection import ConnectionHandler
    from portfootprint.scanner.worker import ScanWorker

    mock_handler = MagicMock(spec=ConnectionHandler)
    mock_handler.scan_port.side_effect = RuntimeError("Mock scan engine crash")

    progress = ProgressTracker(total_tasks=1)
    agg = ResultAggregator(target="localhost", resolved_ip="127.0.0.1", total_ports_count=1)

    worker = ScanWorker(
        connection_handler=mock_handler, progress_tracker=progress, result_aggregator=agg, timeout=1.0, retries=0
    )

    result = worker.execute(80)
    assert result.port == 80
    assert result.state == "UNKNOWN"
    assert "Mock scan engine crash" in result.reason
