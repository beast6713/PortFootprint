"""
Default execution configurations wrapper for PortFootprint.
"""

from portfootprint.core.constants import (
    DEFAULT_COMMON_PORTS,
    DEFAULT_RETRIES,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
)

# Exposed defaults for CLI and Scan configurations
DEFAULT_SCAN_TIMEOUT = DEFAULT_TIMEOUT
DEFAULT_SCAN_RETRIES = DEFAULT_RETRIES
DEFAULT_SCAN_THREADS = DEFAULT_THREADS
DEFAULT_PORTS_LIST = list(DEFAULT_COMMON_PORTS)
