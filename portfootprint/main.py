"""
Main execution entry point for PortFootprint CLI application.
Supports direct scanning flags, high-level subcommands, and interactive console REPL.
"""

import logging
import sys
from typing import Optional

from portfootprint.cli.parser import CommandLineParser
from portfootprint.common.logging import setup_logging
from portfootprint.core.exceptions import PortFootprintError
from portfootprint.core.orchestrator import ScanManager

logger = logging.getLogger("portfootprint.main")


def main() -> None:
    """
    Main orchestrator parsing CLI commands and triggering the scan loop or interactive console.
    Enforces unified error outputs and correct exit status codes.
    """
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    raw_args = sys.argv[1:]

    # 1. If running in an interactive terminal with no arguments, launch interactive console
    if not raw_args and sys.stdin.isatty():
        from portfootprint.cli.console import launch_console
        sys.exit(launch_console())

    # 2. Check for explicit console command
    if raw_args and raw_args[0].lower() in ("console", "interactive"):
        from portfootprint.cli.console import launch_console
        sys.exit(launch_console())

    # 3. Check for high-level convenience subcommands
    if raw_args:
        subcmd = raw_args[0].lower()

        # Doctor health check
        if subcmd in ("doctor", "check"):
            from portfootprint.cli.doctor import DoctorDiagnostic
            try:
                from rich.console import Console
                c = Console()
            except ImportError:
                c = None
            DoctorDiagnostic.run_diagnostics(console=c)
            sys.exit(0)

        # Local open ports detection & scan
        if subcmd in ("local", "listen"):
            from portfootprint.cli.commands import CommandParser, LocalCommand
            cmd = LocalCommand()
            ctx = CommandParser.parse(" ".join(raw_args))
            try:
                from rich.console import Console
                c = Console()
            except ImportError:
                c = None
            sys.exit(cmd.execute(ctx, console=c))

        # Quick scan on top ports
        if subcmd in ("quick", "fast"):
            from portfootprint.cli.commands import CommandParser, QuickCommand
            cmd = QuickCommand()
            ctx = CommandParser.parse(" ".join(raw_args))
            try:
                from rich.console import Console
                c = Console()
            except ImportError:
                c = None
            sys.exit(cmd.execute(ctx, console=c))

        # History subcommand
        if subcmd == "history":
            from portfootprint.cli.commands import CommandContext, HistoryCommand
            h_cmd = HistoryCommand()
            try:
                from rich.console import Console
                c = Console()
            except ImportError:
                c = None
            sys.exit(h_cmd.execute(CommandContext(raw_line="history", command_name="history"), console=c))

        # Compare subcommand
        if subcmd == "compare" and len(raw_args) >= 3:
            raw_args = ["--compare", raw_args[1], raw_args[2]]

        # Scan subcommand prefix: 'scan localhost' -> 'localhost'
        elif subcmd == "scan" and len(raw_args) > 1:
            raw_args = raw_args[1:]

    try:
        # Parse arguments to determine verbosity before logging setup
        parser = CommandLineParser()
        config = parser.parse_args(raw_args)

        # Setup standard logging handler levels
        setup_logging(verbose=config.verbose, log_file=config.log_file)
        logger.debug("Logging initialized successfully.")

        # Intercept History request
        if config.history:
            from portfootprint.core.history import ScanHistoryManager
            hm = ScanHistoryManager()
            history = hm.get_history()
            try:
                from rich.console import Console
                from portfootprint.cli.commands import CommandContext, HistoryCommand
                hc = HistoryCommand()
                hc.execute(CommandContext(raw_line="history", command_name="history"), console=Console())
            except ImportError:
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
        sys.stderr.write(f"\n[!] Error: {e!s}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Execution terminated by user. Exiting.\n")
        sys.exit(130)
    except Exception as e:
        sys.stderr.write(f"\n[!] Unexpected system crash: {e!s}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
