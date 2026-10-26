"""
Unit tests for ScanStatistics, ScanHistoryManager, ScanComparer, and all report format exporters.
"""

import csv
import json
import os

import pytest

from portfootprint.core.comparison import ScanComparer
from portfootprint.core.history import ScanHistoryManager
from portfootprint.core.models import HostResult, PortResult, ScanResult, ServiceMetadata
from portfootprint.core.statistics import ScanStatistics
from portfootprint.reports.csv_report import CsvReportExporter
from portfootprint.reports.html_report import HtmlReportExporter
from portfootprint.reports.json_report import JsonReportExporter
from portfootprint.reports.registry import export_registry
from portfootprint.reports.report_manager import ReportManager


@pytest.fixture
def dummy_scan_result() -> ScanResult:
    """Provides a configured dummy ScanResult instance for validation assertions."""
    ports = [
        PortResult(port=22, state="OPEN", service=ServiceMetadata(service_name="SSH", version="8.2")),
        PortResult(port=80, state="OPEN", service=ServiceMetadata(service_name="HTTP", version="2.4", title="Test")),
        PortResult(port=443, state="CLOSED"),
        PortResult(port=8080, state="FILTERED"),
    ]
    host = HostResult(target="localhost", ip_address="127.0.0.1", ports=ports)
    return ScanResult(
        target="localhost",
        resolved_ip="127.0.0.1",
        total_ports=4,
        hosts=[host],
        start_time=100.0,
        end_time=102.0,
        duration=2.0,
    )


def test_statistics_calculations(dummy_scan_result: ScanResult) -> None:
    """Verifies correctness of ScanStatistics calculations."""
    stats = ScanStatistics.calculate(dummy_scan_result)

    assert stats.total_ports == 4
    assert stats.open_count == 2
    assert stats.closed_count == 1
    assert stats.filtered_count == 1
    assert stats.unknown_count == 0
    assert stats.services_detected == 2
    # 4 ports scanned in 2.0 seconds -> 2.0 ports/sec speed
    assert stats.scan_speed == 2.0
    # Both SSH and HTTP detected once, alphabetical top is HTTP or SSH
    assert stats.most_common_protocol in ("SSH", "HTTP")


def test_scan_history_manager(tmp_path) -> None:
    """Verifies that history manager registers and sorts logs correctly."""
    history_file = tmp_path / "history_test.json"
    manager = ScanHistoryManager(history_file=str(history_file))

    stats = ScanStatistics(
        total_ports=10,
        open_count=2,
        closed_count=8,
        filtered_count=0,
        unknown_count=0,
        scan_speed=5.0,
        services_detected=1,
        most_common_protocol="SSH",
    )

    # Verify initial retrieval is empty
    assert len(manager.get_history()) == 0

    reports = {"json": "rep.json", "html": "rep.html"}
    manager.add_entry(target="localhost", stats=stats, report_paths=reports)

    history = manager.get_history()
    assert len(history) == 1
    assert history[0]["target"] == "localhost"
    assert history[0]["summary"]["total_ports"] == 10
    assert history[0]["reports"]["json"] == "rep.json"


def test_scan_comparer(tmp_path) -> None:
    """Verifies that ScanComparer lists differences between two scan results."""
    old_report = tmp_path / "old.json"
    new_report = tmp_path / "new.json"

    old_data = {
        "target": "localhost",
        "start_time": 100.0,
        "hosts": [
            {
                "ports": [
                    {"port": 22, "state": "OPEN", "service": {"service_name": "SSH", "version": "8.0"}},
                    {"port": 80, "state": "OPEN", "service": {"service_name": "HTTP", "version": "2.4"}},
                ]
            }
        ],
    }

    new_data = {
        "target": "localhost",
        "start_time": 105.0,
        "hosts": [
            {
                "ports": [
                    {
                        "port": 22,
                        "state": "OPEN",
                        "service": {"service_name": "SSH", "version": "8.2"},
                    },  # Changed version
                    {"port": 80, "state": "CLOSED"},  # Removed
                    {"port": 443, "state": "OPEN", "service": {"service_name": "HTTPS", "version": "1.3"}},  # Added
                ]
            }
        ],
    }

    with open(old_report, "w", encoding="utf-8") as f:
        json.dump(old_data, f)
    with open(new_report, "w", encoding="utf-8") as f:
        json.dump(new_data, f)

    comparer = ScanComparer()
    diff = comparer.compare_files(str(old_report), str(new_report))

    # 443 was added
    assert len(diff["added"]) == 1
    assert diff["added"][0]["port"] == 443

    # 80 was removed
    assert len(diff["removed"]) == 1
    assert diff["removed"][0]["port"] == 80

    # 22 version changed from 8.0 to 8.2
    assert len(diff["changed"]) == 1
    assert diff["changed"][0]["port"] == 22
    assert diff["changed"][0]["old_version"] == "8.0"
    assert diff["changed"][0]["new_version"] == "8.2"


def test_json_exporter(tmp_path, dummy_scan_result: ScanResult) -> None:
    """Verifies that JSON exporter writes formatted loadable JSON report."""
    output = tmp_path / "output.json"
    exporter = JsonReportExporter()
    exporter.export(dummy_scan_result, str(output))

    assert os.path.exists(output)
    with open(output, encoding="utf-8") as f:
        data = json.load(f)
        assert data["target"] == "localhost"
        assert data["statistics"]["open"] == 2


def test_csv_exporter(tmp_path, dummy_scan_result: ScanResult) -> None:
    """Verifies that CSV exporter generates standard CSV columns format."""
    output = tmp_path / "output.csv"
    exporter = CsvReportExporter()
    exporter.export(dummy_scan_result, str(output))

    assert os.path.exists(output)
    with open(output, encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)
        # Header + 4 port results
        assert len(rows) == 5
        assert rows[0] == ["Port", "State", "Protocol", "Version", "Banner", "Service Name"]
        assert rows[1][0] == "22"
        assert rows[1][1] == "OPEN"
        assert rows[1][5] == "SSH"


def test_html_exporter(tmp_path, dummy_scan_result: ScanResult) -> None:
    """Verifies HTML report exporter compiles HTML and CSS contents."""
    output = tmp_path / "output.html"
    exporter = HtmlReportExporter()
    exporter.export(dummy_scan_result, str(output))

    assert os.path.exists(output)
    with open(output, encoding="utf-8") as f:
        content = f.read()
        assert "<!DOCTYPE html>" in content
        assert "PortFootprint Scan Report" in content
        assert "port-row-22" in content


def test_report_manager_coordination(tmp_path, dummy_scan_result: ScanResult) -> None:
    """Verifies ReportManager invokes registry lookups and executes exports."""
    paths = {
        "json": str(tmp_path / "coor.json"),
        "csv": str(tmp_path / "coor.csv"),
    }

    manager = ReportManager(paths)
    manager.generate_reports(dummy_scan_result)

    assert os.path.exists(paths["json"])
    assert os.path.exists(paths["csv"])


def test_export_registry_exceptions() -> None:
    """Verifies ExportRegistry throws KeyError for unsupported formats."""
    with pytest.raises(KeyError):
        export_registry.get_exporter("xml_format_not_supported")
