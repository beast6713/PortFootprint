"""
Validation helpers for strings, numeric properties, and parameters.
"""

from typing import Any

from portfootprint.core.exceptions import ConfigurationError


def validate_is_integer(val: Any, name: str) -> int:
    """Verifies that the parameter value is an integer or converts safely."""
    try:
        return int(val)
    except (ValueError, TypeError) as e:
        raise ConfigurationError(f"Parameter '{name}' must be a valid integer.") from e


def validate_is_float(val: Any, name: str) -> float:
    """Verifies that the parameter value is a float or converts safely."""
    try:
        return float(val)
    except (ValueError, TypeError) as e:
        raise ConfigurationError(f"Parameter '{name}' must be a valid float value.") from e


def validate_range(val: float, min_val: float, max_val: float, name: str) -> None:
    """Ensures value sits within boundaries."""
    if not (min_val <= val <= max_val):
        raise ConfigurationError(f"Parameter '{name}' value {val} must stand between {min_val} and {max_val}.")
