"""
Unit tests for the PortFootprint core configuration, progress, and aggregation models.
"""

import socket
from unittest.mock import MagicMock, patch

import pytest

from portfootprint.core.config import ScanConfiguration
from portfootprint.core.exceptions import ConfigurationError
from portfootprint.core.models import PortResult
from portfootprint.core.progress import ProgressTracker
from portfootprint.core.result_aggregator import ResultAggregator


def test_scan_configuration_validation() -> None:
    """Verifies that invalid configuration inputs raise ConfigurationError."""
    # Invalid target
    with pytest.raises(ConfigurationError):
        ScanConfiguration(target="", ports=[80])

    # Thread limit error
    with pytest.raises(ConfigurationError):
        ScanConfiguration(target="localhost", ports=[80], threads=0)
    with pytest.raises(ConfigurationError):
        ScanConfiguration(target="localhost", ports=[80], threads=5000)

    # Invalid timeout parameter
    with pytest.raises(ConfigurationError):
        ScanConfiguration(target="localhost", ports=[80], timeout=-1.0)

    # Empty ports list
    with pytest.raises(ConfigurationError):
        ScanConfiguration(target="localhost", ports=[])


def test_progress_tracker() -> None:
    """Verifies status tracking logic on the ProgressTracker."""
    tracker = ProgressTracker(total_tasks=10)

    assert tracker.get_progress_percentage() == 0.0

    # Simulates start and complete
    tracker.start_task()
    assert tracker.active_workers == 1

    tracker.complete_task()
    assert tracker.active_workers == 0
    assert tracker.completed_tasks == 1
    assert tracker.get_progress_percentage() == 10.0


def test_result_aggregator() -> None:
    """Verifies that the ResultAggregator compiles outputs cleanly."""
    agg = ResultAggregator(target="localhost", resolved_ip="127.0.0.1", total_ports_count=2)

    res1 = PortResult(port=80, state="OPEN", reason="Success", duration=0.1)
    res2 = PortResult(port=443, state="CLOSED", reason="Refused", duration=0.2)

    agg.add_port_result(res2)
    agg.add_port_result(res1)

    # Compilation
    scan_result = agg.compile()

    assert scan_result.target == "localhost"
    assert scan_result.resolved_ip == "127.0.0.1"
    assert scan_result.total_ports == 2
    assert len(scan_result.hosts) == 1

    host_res = scan_result.hosts[0]
    # Check that ports are sorted ascending
    assert host_res.ports[0].port == 80
    assert host_res.ports[1].port == 443
    assert scan_result.duration >= 0.0


@patch("portfootprint.core.orchestrator.TargetResolver")
@patch("portfootprint.core.orchestrator.ScanScheduler")
def test_scan_manager_execution(mock_scheduler_class: MagicMock, mock_resolver_class: MagicMock) -> None:
    """Verifies the ScanManager orchestration execution flow using mocks."""
    # Configure mock resolver
    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = ("127.0.0.1", socket.AF_INET)
    mock_resolver_class.return_value = mock_resolver

    # Configure mock scheduler
    mock_scheduler = MagicMock()
    mock_scheduler_class.return_value = mock_scheduler

    # Setup config
    config = ScanConfiguration(target="localhost", ports=[80, 443])

    from portfootprint.core.orchestrator import ScanManager

    manager = ScanManager(config)

    # Execute orchestrator
    result = manager.execute()

    assert result.target == "localhost"
    assert result.resolved_ip == "127.0.0.1"
    assert result.total_ports == 2
    mock_resolver.resolve.assert_called_once_with("localhost")
    mock_scheduler.run.assert_called_once()
