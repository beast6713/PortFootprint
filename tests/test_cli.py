"""
Unit tests for the PortFootprint CommandLineParser.
"""

# pyrefly: ignore [missing-import]
import pytest

from portfootprint.cli.parser import CommandLineParser
from portfootprint.core.exceptions import InvalidPortError


def test_cli_parser_defaults() -> None:
    """Verifies that the parser sets expected defaults for target scanning."""
    parser = CommandLineParser()
    config = parser.parse_args(["localhost"])

    assert config.target == "localhost"
    assert len(config.ports) > 0
    assert config.threads == 20
    assert config.timeout == 2.0
    assert config.retries == 1
    assert not config.verbose


def test_cli_parser_custom_values() -> None:
    """Verifies parsing of custom parameter arguments."""
    parser = CommandLineParser()
    config = parser.parse_args(
        ["scanme.nmap.org", "-p", "80,443", "--threads", "50", "--timeout", "1.5", "--retries", "2", "--verbose"]
    )

    assert config.target == "scanme.nmap.org"
    assert config.ports == [80, 443]
    assert config.threads == 50
    assert config.timeout == 1.5
    assert config.retries == 2
    assert config.verbose


def test_cli_parser_invalid_target() -> None:
    """Verifies that empty targets or target errors raise expected SystemExit."""
    parser = CommandLineParser()
    with pytest.raises(SystemExit):
        parser.parse_args([])  # Missing target


def test_cli_parser_invalid_ports() -> None:
    """Verifies that malformed port strings trigger InvalidPortError."""
    parser = CommandLineParser()
    with pytest.raises(InvalidPortError):
        parser.parse_args(["localhost", "-p", "abc"])
