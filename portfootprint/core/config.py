"""
Immutable ScanConfiguration definition for PortFootprint parameters validation.
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from portfootprint.core.constants import (
    MAX_PORT,
    MAX_THREADS_LIMIT,
    MIN_PORT,
    MIN_THREADS_LIMIT,
)
from portfootprint.core.exceptions import ConfigurationError


@dataclass(frozen=True)
class ScanConfiguration:
    """
    Scan configurations object holding runtime properties.
    Ensures safe constraints validation during construction.
    """

    target: str
    ports: list[int] = field(default_factory=list)
    threads: int = 20
    timeout: float = 2.0
    retries: int = 1
    verbose: bool = False
    json_report: Optional[str] = None
    csv_report: Optional[str] = None
    html_report: Optional[str] = None
    all_reports: bool = False
    history: bool = False
    compare: Optional[list[str]] = None
    log_file: Optional[str] = None

    def __post_init__(self) -> None:
        # Bypass validation checks for history index retrieval or scan comparisons commands
        if self.history or self.compare:
            return

        # Validate target parameter
        if not self.target:
            raise ConfigurationError("Target host cannot be empty.")

        # Validate threads range
        if not (MIN_THREADS_LIMIT <= self.threads <= MAX_THREADS_LIMIT):
            raise ConfigurationError(f"Thread count must be between {MIN_THREADS_LIMIT} and {MAX_THREADS_LIMIT}.")

        # Validate timeout value
        if self.timeout <= 0.0:
            raise ConfigurationError("Socket timeout parameter must be greater than zero.")

        # Validate retries count
        if self.retries < 0:
            raise ConfigurationError("Socket retries count cannot be negative.")

        # Validate ports content
        if not self.ports:
            raise ConfigurationError("Scan ports list cannot be empty.")

        for port in self.ports:
            if not (MIN_PORT <= port <= MAX_PORT):
                raise ConfigurationError(f"Port number {port} is out of valid range ({MIN_PORT}-{MAX_PORT}).")

    @classmethod
    def load_config_file(cls, path: str = "config.json") -> dict[str, Any]:
        """
        Attempts to read configuration values from a JSON config file.
        Returns a dict of parsed parameters or empty dict if missing/corrupt.
        """
        import json
        import os

        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception:  # nosec B110
                pass
        return {}
