"""
Logging configurations initialization module for PortFootprint.
"""

import logging
import sys
from typing import Optional


def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    """
    Configures standard library logging configurations.
    Enables verbose DEBUG outputs when parameter flag is active.
    Appends structured logs to log_file if provided.
    """
    root_logger = logging.getLogger("portfootprint")
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid duplicate handlers if setup_logging runs multiple times
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    # 1. Console Stream Handler
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    if verbose:
        stream_formatter = logging.Formatter(
            "[%(asctime)s] [%(threadName)s] [%(levelname)s] %(name)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        stream_formatter = logging.Formatter("[*] %(message)s")

    stream_handler.setFormatter(stream_formatter)
    root_logger.addHandler(stream_handler)

    # 2. Optional File Handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                "%(asctime)s [%(threadName)s] [%(levelname)s] %(name)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
        except (OSError, ValueError) as e:
            # Output warning if log file cannot be created
            root_logger.exception(f"Failed to initialize file logger at '{log_file}': {e!s}")
