"""
CommandLineParser setting up argparse parameters and flags for PortFootprint.
"""

import argparse
import sys
from collections.abc import Sequence
from typing import Optional

from portfootprint.core.config import ScanConfiguration
from portfootprint.core.defaults import (
    DEFAULT_PORTS_LIST,
    DEFAULT_SCAN_RETRIES,
    DEFAULT_SCAN_THREADS,
    DEFAULT_SCAN_TIMEOUT,
)
from portfootprint.core.version import __version__
from portfootprint.scanner.port_parser import PortParser


class CommandLineParser:
    """
    Parses and validates CLI arguments.
    Builds the corresponding ScanConfiguration dataclass.
    """

    def __init__(self, port_parser: Optional[PortParser] = None) -> None:
        self.port_parser = port_parser or PortParser()
        self.parser = self._build_parser()

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="portfootprint",
            description="PortFootprint - A professional, dependency-free TCP Connect port scanner.",
            add_help=True,
        )

        parser.add_argument("target", nargs="?", help="Target hostname or IP address to scan.")

        parser.add_argument(
            "-p",
            "--ports",
            dest="ports",
            help="Ports specification (e.g. '80', '22,80,443', '20-100', '1-65535'). "
            "Defaults to common top ports if omitted.",
        )

        parser.add_argument("-t", "--threads", type=int, dest="threads", help="Number of worker threads.")

        parser.add_argument("-w", "--timeout", type=float, dest="timeout", help="Socket timeout in seconds.")

        parser.add_argument("-r", "--retries", type=int, dest="retries", help="Number of socket connect retries.")

        parser.add_argument(
            "-v", "--verbose", action="store_true", dest="verbose", help="Enable verbose output with logging details."
        )

        parser.add_argument(
            "-V",
            "--version",
            action="version",
            version=f"PortFootprint v{__version__}",
            help="Print version information and exit.",
        )

        # Reporting & Statistics Flags
        parser.add_argument("--json", dest="json_report", help="Path to export the structured JSON report.")

        parser.add_argument("--csv", dest="csv_report", help="Path to export the flat CSV report.")

        parser.add_argument("--html", dest="html_report", help="Path to export the premium HTML report.")

        parser.add_argument(
            "--all-reports",
            action="store_true",
            dest="all_reports",
            help="Generates JSON, CSV, and HTML reports with default filenames.",
        )

        parser.add_argument(
            "--history", action="store_true", dest="history", help="Displays local scan history index records."
        )

        parser.add_argument(
            "--compare",
            nargs=2,
            metavar=("OLD_JSON", "NEW_JSON"),
            dest="compare",
            help="Compares two JSON scan reports to discover changes.",
        )

        parser.add_argument("--log-file", dest="log_file", help="Path to save log files output.")

        return parser

    def parse_args(self, args: Optional[Sequence[str]] = None) -> ScanConfiguration:
        """
        Parses arguments sequence, merges config file defaults, and returns configuration.
        """
        parsed = self.parser.parse_args(args)

        # Bypass target required validation if querying history or running comparison checks
        if not parsed.target and not (parsed.history or parsed.compare):
            self.parser.error("the following arguments are required: target")

        # Resolve config.json file defaults
        config_data = ScanConfiguration.load_config_file()

        # Check raw CLI arguments to determine override policies
        cli_args = args if args is not None else sys.argv[1:]

        def was_passed(*flags: str) -> bool:
            return any(flag in cli_args for flag in flags)

        # Resolve concurrency properties
        threads = parsed.threads
        if threads is None:
            threads = int(config_data["threads"]) if "threads" in config_data else DEFAULT_SCAN_THREADS

        timeout = parsed.timeout
        if timeout is None:
            timeout = float(config_data["timeout"]) if "timeout" in config_data else DEFAULT_SCAN_TIMEOUT

        retries = parsed.retries
        if retries is None:
            retries = int(config_data["retries"]) if "retries" in config_data else DEFAULT_SCAN_RETRIES

        verbose = parsed.verbose
        if not was_passed("-v", "--verbose") and "verbose" in config_data:
            verbose = bool(config_data["verbose"])

        log_file = parsed.log_file
        if not was_passed("--log-file") and "log_file" in config_data:
            log_file = config_data["log_file"]

        # Resolve default report paths from config if --all-reports or config-defined defaults are active
        json_report = parsed.json_report
        csv_report = parsed.csv_report
        html_report = parsed.html_report

        default_reports_cfg = config_data.get("default_reports", {})

        # Override if --all-reports is set
        if parsed.all_reports:
            json_report = json_report or "report.json"
            csv_report = csv_report or "report.csv"
            html_report = html_report or "report.html"
        else:
            if not was_passed("--json") and "json" in default_reports_cfg:
                json_report = default_reports_cfg["json"]
            if not was_passed("--csv") and "csv" in default_reports_cfg:
                csv_report = default_reports_cfg["csv"]
            if not was_passed("--html") and "html" in default_reports_cfg:
                html_report = default_reports_cfg["html"]

        # Resolve ports mapping
        ports = self.port_parser.parse(parsed.ports) if parsed.ports else DEFAULT_PORTS_LIST

        # Return validated ScanConfiguration instance
        return ScanConfiguration(
            target=parsed.target or "dummy",
            ports=ports,
            threads=threads,
            timeout=timeout,
            retries=retries,
            verbose=verbose,
            json_report=json_report,
            csv_report=csv_report,
            html_report=html_report,
            all_reports=parsed.all_reports,
            history=parsed.history,
            compare=parsed.compare,
            log_file=log_file,
        )
