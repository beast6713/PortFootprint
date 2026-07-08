"""
Centralized constant definitions for PortFootprint parameters.
"""

# Connection Defaults
DEFAULT_TIMEOUT: float = 2.0
DEFAULT_RETRIES: int = 1
DEFAULT_THREADS: int = 20

# Thread Pool Limits
MAX_THREADS_LIMIT: int = 1000
MIN_THREADS_LIMIT: int = 1

# Port Ranges
MIN_PORT: int = 1
MAX_PORT: int = 65535

# Default Ports collection (Common top ports if none specified)
DEFAULT_COMMON_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080
)

# Socket status flags mapping
PORT_STATUS_OPEN = "OPEN"
PORT_STATUS_CLOSED = "CLOSED"
PORT_STATUS_FILTERED = "FILTERED"
PORT_STATUS_UNKNOWN = "UNKNOWN"
