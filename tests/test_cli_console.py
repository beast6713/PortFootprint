"""
Unit and integration tests for the PortFootprint Interactive CLI, Banner, Doctor, and Commands.
"""

from unittest.mock import patch

import pytest

from portfootprint.cli.banner import PortFootprintBanner
from portfootprint.cli.commands import (
    ClearCommand,
    CommandContext,
    CommandParser,
    DoctorCommand,
    HistoryCommand,
    LocalCommand,
    QuickCommand,
    ReportCommand,
    ScanCommand,
    VersionCommand,
    build_default_command_registry,
)
from portfootprint.cli.doctor import DoctorDiagnostic
from portfootprint.cli.formatter import TerminalFormatter
from portfootprint.core.models import HostResult, PortResult, ScanResult, ServiceMetadata
from portfootprint.main import main


def test_banner_rendering() -> None:
    """Verifies banner get_counts and render execution without error."""
    protocols, exporters, history = PortFootprintBanner.get_counts()
    assert protocols >= 1
    assert exporters == 3
    assert history >= 0

    # Test render with console=None (plain text path)
    PortFootprintBanner.render(console=None, status="READY")
    PortFootprintBanner.render(console=None, status="WARNING")


def test_doctor_diagnostics() -> None:
    """Verifies doctor diagnostic checks run and report health status."""
    status, results = DoctorDiagnostic.run_diagnostics(console=None)
    assert status in ("READY", "WARNING", "ERROR")
    assert len(results) >= 5

    names = [r["name"] for r in results]
    assert "Python Environment" in names
    assert "TCP Socket Subsystem" in names
    assert "Protocol Fingerprinters" in names


def test_command_parser_tokens() -> None:
    """Verifies command tokenizer extracts command, args, and option flags."""
    ctx = CommandParser.parse("scan 127.0.0.1 -p 80,443 --threads 50 --verbose")
    assert ctx.command_name == "scan"
    assert ctx.args == ["127.0.0.1"]
    assert ctx.options["p"] == "80,443"
    assert ctx.options["threads"] == "50"
    assert ctx.options["verbose"] is True

    # Empty line
    ctx_empty = CommandParser.parse("   ")
    assert ctx_empty.command_name == ""


def test_version_command() -> None:
    """Verifies version command outputs release version."""
    cmd = VersionCommand()
    assert cmd.name == "version"
    res = cmd.execute(CommandContext(raw_line="version", command_name="version"), console=None)
    assert res == 0


def test_clear_command() -> None:
    """Verifies clear command runs."""
    cmd = ClearCommand()
    with patch("sys.stdout.write") as mock_write:
        res = cmd.execute(CommandContext(raw_line="clear", command_name="clear"), console=None)
        assert res == 0
        mock_write.assert_called_once()


def test_help_command() -> None:
    """Verifies help command displays general overview and specific command docs."""
    reg = build_default_command_registry()
    help_cmd = reg["help"]

    # General help
    assert help_cmd.execute(CommandContext(raw_line="help", command_name="help"), console=None) == 0

    # Specific command help
    assert help_cmd.execute(CommandContext(raw_line="help scan", command_name="help", args=["scan"]), console=None) == 0

    # Unknown command help
    assert (
        help_cmd.execute(
            CommandContext(raw_line="help nonexistent", command_name="help", args=["nonexistent"]), console=None
        )
        == 1
    )


def test_doctor_command() -> None:
    """Verifies DoctorCommand executes diagnostics."""
    cmd = DoctorCommand()
    assert cmd.execute(CommandContext(raw_line="doctor", command_name="doctor"), console=None) == 0


def test_history_command() -> None:
    """Verifies HistoryCommand fetches and displays records."""
    cmd = HistoryCommand()
    with patch("portfootprint.core.history.ScanHistoryManager.get_history", return_value=[]):
        assert cmd.execute(CommandContext(raw_line="history", command_name="history"), console=None) == 0


def test_quick_command() -> None:
    """Verifies QuickCommand triggers ScanManager execution."""
    cmd = QuickCommand()
    # Missing target
    assert cmd.execute(CommandContext(raw_line="quick", command_name="quick"), console=None) == 1

    # Valid target
    with patch("portfootprint.core.orchestrator.ScanManager.execute") as mock_exec:
        res = cmd.execute(
            CommandContext(raw_line="quick localhost", command_name="quick", args=["localhost"]), console=None
        )
        assert res == 0
        mock_exec.assert_called_once()


def test_local_command() -> None:
    """Verifies LocalCommand detects ports and triggers scan."""
    cmd = LocalCommand()
    with (
        patch("portfootprint.cli.doctor.DoctorDiagnostic.detect_local_listening_ports", return_value=[80, 443]),
        patch("portfootprint.core.orchestrator.ScanManager.execute") as mock_exec,
    ):
        res = cmd.execute(CommandContext(raw_line="local", command_name="local"), console=None)
        assert res == 0
        mock_exec.assert_called_once()


def test_scan_command() -> None:
    """Verifies ScanCommand option parsing and scan trigger."""
    cmd = ScanCommand()
    # Missing target
    assert cmd.execute(CommandContext(raw_line="scan", command_name="scan"), console=None) == 1

    # Valid target with options
    with patch("portfootprint.core.orchestrator.ScanManager.execute") as mock_exec:
        ctx = CommandContext(
            raw_line="scan 127.0.0.1 -p 80 --threads 10",
            command_name="scan",
            args=["127.0.0.1"],
            options={"p": "80", "threads": "10"},
        )
        res = cmd.execute(ctx, console=None)
        assert res == 0
        mock_exec.assert_called_once()


def test_terminal_formatter_rich_scan_result() -> None:
    """Verifies print_rich_scan_result displays properly."""
    port = PortResult(port=80, state="OPEN", service=ServiceMetadata(service_name="HTTP", title="My App"))
    host = HostResult(target="localhost", ip_address="127.0.0.1", ports=[port])
    result = ScanResult(
        target="localhost",
        resolved_ip="127.0.0.1",
        total_ports=1,
        hosts=[host],
        start_time=0.0,
        end_time=1.0,
        duration=1.0,
    )
    # Should run cleanly
    TerminalFormatter.print_rich_scan_result(result, verbose=True)
    TerminalFormatter.print_rich_scan_result(result, verbose=False)


def test_main_subcommands() -> None:
    """Verifies direct execution of subcommands via main.py."""
    # Subcommand: doctor
    with patch("sys.argv", ["main.py", "doctor"]), pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0

    # Subcommand: history
    with (
        patch("sys.argv", ["main.py", "history"]),
        patch("portfootprint.core.history.ScanHistoryManager.get_history", return_value=[]),
        pytest.raises(SystemExit) as exc,
    ):
        main()
    assert exc.value.code == 0

    # Subcommand: report
    with (
        patch("sys.argv", ["main.py", "report", "html"]),
        patch("portfootprint.cli.commands.webbrowser.open"),
        pytest.raises(SystemExit) as exc,
    ):
        main()
    assert exc.value.code == 0


def test_report_command() -> None:
    """Verifies ReportCommand catalog rendering, discovery, and selection logic."""
    cmd = ReportCommand()
    assert cmd.name == "report"
    assert "reports" in cmd.aliases

    # Test format catalog display without options (non-interactive in tests)
    res = cmd.execute(CommandContext(raw_line="report", command_name="report"), console=None)
    assert res == 0

    # Test open non-existent file
    res_missing = cmd.execute(
        CommandContext(
            raw_line="report open non_existent.html", command_name="report", args=["open", "non_existent.html"]
        ),
        console=None,
    )
    assert res_missing == 1

    # Test selection options
    with patch("portfootprint.cli.commands.webbrowser.open"):
        assert (
            cmd.execute(CommandContext(raw_line="report html", command_name="report", args=["html"]), console=None) == 0
        )
        assert (
            cmd.execute(CommandContext(raw_line="report json", command_name="report", args=["json"]), console=None) == 0
        )
        assert (
            cmd.execute(CommandContext(raw_line="report csv", command_name="report", args=["csv"]), console=None) == 0
        )
        assert (
            cmd.execute(CommandContext(raw_line="report all", command_name="report", args=["all"]), console=None) == 0
        )

    # Test with Rich Console if available
    try:
        from rich.console import Console

        c = Console(record=True)
        assert cmd.execute(CommandContext(raw_line="report", command_name="report"), console=c) == 0
        output = c.export_text()
        assert "Report Formats & Selection Guide" in output
    except ImportError:
        pass


def test_terminal_formatter_reports_section() -> None:
    """Verifies print_reports_section with active reports and plain text / Rich fallbacks."""
    # Empty reports dictionary: should return silently
    TerminalFormatter.print_reports_section({})

    # Mock reports
    sample_reports = {
        "html": "sample_report.html",
        "json": "sample_report.json",
        "csv": "sample_report.csv",
    }

    # Plain text rendering (console=None)
    TerminalFormatter.print_reports_section(sample_reports, console=None)

    # Rich rendering if available
    try:
        from rich.console import Console

        c = Console(record=True)
        TerminalFormatter.print_reports_section(sample_reports, console=c)
        rendered = c.export_text()
        assert "Generated Reports" in rendered
        assert "sample_report.html" in rendered
    except ImportError:
        pass
