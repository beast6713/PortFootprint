"""
Unit tests for PortParser, TargetResolver validations, and host checking helpers.
"""

# pyrefly: ignore [missing-import]
import pytest

from portfootprint.common.validation import validate_is_float, validate_is_integer, validate_range
from portfootprint.core.exceptions import ConfigurationError, InvalidPortError
from portfootprint.scanner.port_parser import PortParser
from portfootprint.scanner.resolver import TargetResolver


def test_port_parser_ranges() -> None:
    """Verifies that the PortParser handles lists and range patterns cleanly."""
    parser = PortParser()

    # Single ports list
    assert parser.parse("22,80,443") == [22, 80, 443]

    # Ranges
    assert parser.parse("80-83") == [80, 81, 82, 83]

    # Mixed and spaces
    assert parser.parse(" 22, 80-82, 443 ") == [22, 80, 81, 82, 443]

    # Duplicates removal
    assert parser.parse("80,80,22,22-24") == [22, 23, 24, 80]


def test_port_parser_validation_errors() -> None:
    """Verifies that invalid port formatting throws InvalidPortError exceptions."""
    parser = PortParser()

    with pytest.raises(InvalidPortError):
        parser.parse("abc")

    with pytest.raises(InvalidPortError):
        parser.parse("70000")

    with pytest.raises(InvalidPortError):
        parser.parse("-5")

    with pytest.raises(InvalidPortError):
        parser.parse("80-22")  # Invalid range start > end


def test_target_resolver_validation() -> None:
    """Verifies DNS hostname regex parsing conditions."""
    resolver = TargetResolver()

    assert resolver.is_valid_hostname("localhost")
    assert resolver.is_valid_hostname("google.com")
    assert resolver.is_valid_hostname("scanme.nmap.org")
    assert resolver.is_valid_hostname("sub-domain.target.dns.local")

    assert not resolver.is_valid_hostname("")
    assert not resolver.is_valid_hostname("target_dns.com")  # Underscores invalid in DNS hostname host strings
    assert not resolver.is_valid_hostname("-target.com")


def test_validation_helpers() -> None:
    """Verifies general validation functions behavior."""
    assert validate_is_integer("123", "test") == 123
    assert validate_is_float("1.25", "test") == 1.25

    # Check invalid inputs raise ConfigurationError
    with pytest.raises(ConfigurationError):
        validate_is_integer("abc", "test")

    with pytest.raises(ConfigurationError):
        validate_is_float("abc", "test")

    # Check range validations
    validate_range(5.0, 1.0, 10.0, "test")  # Should pass

    with pytest.raises(ConfigurationError):
        validate_range(11.0, 1.0, 10.0, "test")
