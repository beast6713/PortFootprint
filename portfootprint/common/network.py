"""
Networking helpers for checking host configurations and active interfaces.
"""

import socket


def get_local_ip() -> str:
    """Attempts to find the default local outbound IP interface."""
    # We open a dummy UDP connection to resolve outbound IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not send packets, just configures OS routing lookup
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return str(ip)
