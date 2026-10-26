"""
Unified exception hierarchy for PortFootprint.
"""


class PortFootprintError(Exception):
    """Base exception for all PortFootprint errors."""

    pass


class TargetResolutionError(PortFootprintError):
    """Raised when host resolution fails or domain format is invalid."""

    pass


class InvalidPortError(PortFootprintError):
    """Raised when a port specification is out of bounds or malformed."""

    pass


class ScanExecutionError(PortFootprintError):
    """Raised when the scanner scheduler encounters execution or resource errors."""

    pass


class ConnectionTimeoutError(ScanExecutionError):
    """Raised when a port socket connection times out."""

    pass


class ConfigurationError(PortFootprintError):
    """Raised when scan configurations fail validation."""

    pass
