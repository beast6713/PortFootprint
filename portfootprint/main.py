"""
Main execution entry point for PortFootprint CLI application.
"""

import logging
import sys

from portfootprint.cli.parser import CommandLineParser
from portfootprint.common.logging import setup_logging
from portfootprint.core.exceptions import PortFootprintError
from portfootprint.core.orchestrator import ScanManager

logger = logging.getLogger("portfootprint.main")


def main() -> None:
    """
    Main orchestrator parsing CLI commands and triggering the scan loop.
    Enforces unified error outputs and correct exit status codes.
    """
    try:
        # Parse arguments first to determine verbosity before logging setup
        parser = CommandLineParser()
        # Parse command line list (excluding script path)
        config = parser.parse_args(sys.argv[1:])

        # Setup standard logging handler levels
        setup_logging(verbose=config.verbose, log_file=config.log_file)
        logger.debug("Logging initialized successfully.")

        # Intercept History request
        if config.history:
            from portfootprint.core.history import ScanHistoryManager
            hm = ScanHistoryManager()
            history = hm.get_history()
            print("=================================================")
            print("PortFootprint Scan History Index")
            print("=================================================")
            if not history:
                print("No scan history records found.")
            else:
                for entry in history:
                    print(f"[{entry['timestamp']}] Target: {entry['target']}")
                    s = entry['summary']
                    print(f"  Summary: Total {s['total_ports']} | Open {s['open']} | Filtered {s['filtered']} | Closed {s['closed']}")
                    if entry['reports']:
                        active_reps = [f"{k}: {v}" for k, v in entry['reports'].items() if v]
                        if active_reps:
                            print(f"  Reports: {', '.join(active_reps)}")
            print("=================================================")
            sys.exit(0)

        # Intercept Comparison request
        if config.compare:
            from portfootprint.cli.formatter import TerminalFormatter
            from portfootprint.core.comparison import ScanComparer
            old_path, new_path = config.compare
            comparer = ScanComparer()
            diff = comparer.compare_files(old_path, new_path)
            TerminalFormatter.print_comparison(diff)
            sys.exit(0)

        # Initialize and trigger execution scan
        manager = ScanManager(config)
        manager.execute()

    except PortFootprintError as e:
        # Catch anticipated project exceptions and output clean error messages
        sys.stderr.write(f"\n[!] Error: {e!s}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        # Catch SIGINT controls
        sys.stderr.write("\n[!] Execution terminated by user. Exiting.\n")
        sys.exit(130)
    except Exception as e:
        # Catch remaining runtime exceptions
        sys.stderr.write(f"\n[!] Unexpected system crash: {e!s}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
