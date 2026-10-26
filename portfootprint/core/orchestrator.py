"""
ScanManager orchestrating the overall resolution, scan execution, and results aggregation.
"""

import logging
import sys

from portfootprint.cli.formatter import TerminalFormatter
from portfootprint.cli.progress import ConsoleProgressRenderer
from portfootprint.core.config import ScanConfiguration
from portfootprint.core.models import ScanResult
from portfootprint.core.progress import ProgressTracker
from portfootprint.core.result_aggregator import ResultAggregator
from portfootprint.scanner.connection import ConnectionHandler
from portfootprint.scanner.resolver import TargetResolver
from portfootprint.scanner.scheduler import ScanScheduler
from portfootprint.scanner.worker import ScanWorker

logger = logging.getLogger("portfootprint.core.orchestrator")


class ScanManager:
    """
    Coordinates target lookup, resource initialization, threading scheduling,
    and progress rendering across the scanning execution pipeline.
    """

    def __init__(self, config: ScanConfiguration) -> None:
        self.config = config
        self.resolver = TargetResolver()
        self.scheduler = ScanScheduler(threads=config.threads)
        self.progress_renderer = ConsoleProgressRenderer()

    def execute(self) -> ScanResult:
        """
        Coordinates Host resolution, task setup, and concurrency scheduling.
        Outputs terminal statistics reports upon completion.
        """
        # 1. Resolve host targets
        logger.debug(f"Initiating target resolution check for '{self.config.target}'...")
        resolved_ip, address_family = self.resolver.resolve(self.config.target)
        logger.debug(f"Target '{self.config.target}' resolved to IP '{resolved_ip}'.")

        # 2. Render initial pre-scan console setup
        TerminalFormatter.print_banner()
        TerminalFormatter.print_pre_scan(
            target=self.config.target,
            resolved_ip=resolved_ip,
            total_ports=len(self.config.ports),
            threads=self.config.threads,
        )

        # 3. Setup aggregators & progress trackers
        total_ports = len(self.config.ports)
        aggregator = ResultAggregator(target=self.config.target, resolved_ip=resolved_ip, total_ports_count=total_ports)

        # We hook a progress update callback inside the tracker initialization
        def progress_callback() -> None:
            # Render updated progress stats
            stats = progress.get_stats()
            # Do not display progress bar if verbose mode logging is enabled
            if not self.config.verbose:
                self.progress_renderer.render(stats)

        progress = ProgressTracker(total_tasks=total_ports, on_step_callback=progress_callback)

        # Setup connection handler and worker
        conn_handler = ConnectionHandler(ip_address=resolved_ip, address_family=address_family)

        worker = ScanWorker(
            connection_handler=conn_handler,
            progress_tracker=progress,
            result_aggregator=aggregator,
            timeout=self.config.timeout,
            retries=self.config.retries,
            verbose=self.config.verbose,
        )

        # 4. Trigger Scheduler scanning process
        try:
            # Show initial 0% progress bar if not verbose
            if not self.config.verbose:
                self.progress_renderer.render(progress.get_stats())

            self.scheduler.run(ports=self.config.ports, worker=worker)

            # Clear progress indicator carriage returns
            if not self.config.verbose:
                self.progress_renderer.clear()

        except KeyboardInterrupt:
            # Under Ctrl+C, log termination states and return partial outputs
            if not self.config.verbose:
                self.progress_renderer.clear()
            logger.warning("Scan run aborted. Presenting partial results gathered.")

        # 5. Compile and export final outputs
        scan_result = aggregator.compile()
        if sys.stdout.isatty():
            TerminalFormatter.print_rich_scan_result(scan_result, verbose=self.config.verbose)
        else:
            TerminalFormatter.print_scan_result(scan_result, verbose=self.config.verbose)

        # Trigger ReportManager and ScanHistoryManager integrations
        reports = {}
        if self.config.json_report:
            reports["json"] = self.config.json_report
        if self.config.csv_report:
            reports["csv"] = self.config.csv_report
        if self.config.html_report:
            reports["html"] = self.config.html_report

        if reports:
            try:
                from portfootprint.reports.report_manager import ReportManager

                rm = ReportManager(reports)
                rm.generate_reports(scan_result)
                TerminalFormatter.print_reports_section(reports)
            except Exception as e:
                logger.exception(f"Failed to generate output reports: {e!s}")

        try:
            from portfootprint.core.history import ScanHistoryManager
            from portfootprint.core.statistics import ScanStatistics

            stats = ScanStatistics.calculate(scan_result)
            history_manager = ScanHistoryManager()
            history_manager.add_entry(self.config.target, stats, reports)
        except Exception as e:
            logger.exception(f"Failed to write scan history database entry: {e!s}")

        return scan_result
