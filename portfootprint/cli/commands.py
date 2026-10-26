"""
Command Definitions and Dispatcher for PortFootprint CLI Console.
Implements modular, user-friendly interactive commands.
"""

import os
import shlex
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    Console = None  # type: ignore
    Panel = None  # type: ignore
    Table = None  # type: ignore
    RICH_AVAILABLE = False

from portfootprint.core.config import ScanConfiguration
from portfootprint.core.defaults import (
    DEFAULT_PORTS_LIST,
    DEFAULT_SCAN_RETRIES,
    DEFAULT_SCAN_THREADS,
    DEFAULT_SCAN_TIMEOUT,
)
from portfootprint.core.orchestrator import ScanManager
from portfootprint.core.version import __version__


@dataclass
class CommandContext:
    """Encapsulates a parsed command call."""

    raw_line: str
    command_name: str
    args: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


class CommandParser:
    """Parses raw console input strings into CommandContext."""

    @classmethod
    def parse(cls, input_line: str) -> CommandContext:
        clean = input_line.strip()
        if not clean:
            return CommandContext(raw_line="", command_name="")

        try:
            tokens = shlex.split(clean)
        except ValueError:
            tokens = clean.split()

        if not tokens:
            return CommandContext(raw_line=clean, command_name="")

        cmd_name = tokens[0].lower()
        raw_args = tokens[1:]

        args: list[str] = []
        options: dict[str, Any] = {}

        i = 0
        while i < len(raw_args):
            t = raw_args[i]
            if t.startswith("--"):
                key = t[2:].replace("-", "_")
                if i + 1 < len(raw_args) and not raw_args[i + 1].startswith("-"):
                    options[key] = raw_args[i + 1]
                    i += 2
                else:
                    options[key] = True
                    i += 1
            elif t.startswith("-") and len(t) > 1 and not (len(t) > 1 and t[1].isdigit()):
                key = t[1:]
                if i + 1 < len(raw_args) and not raw_args[i + 1].startswith("-"):
                    options[key] = raw_args[i + 1]
                    i += 2
                else:
                    options[key] = True
                    i += 1
            else:
                args.append(t)
                i += 1

        return CommandContext(raw_line=clean, command_name=cmd_name, args=args, options=options)


class BaseCommand:
    """Base class for all console commands."""

    name: str = ""
    description: str = ""
    syntax: str = ""
    aliases: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        raise NotImplementedError


class ScanCommand(BaseCommand):
    """Executes a configurable TCP port scan and service fingerprint."""

    name = "scan"
    description = "Scan a target host with custom ports, threads, and reports"
    syntax = "scan <target> [-p PORTS] [-t THREADS] [-w TIMEOUT] [--all-reports] [--html FILE] [--verbose]"
    aliases = ("run", "s")
    examples = (
        "scan 127.0.0.1",
        "scan 127.0.0.1 -p 80,443,3306",
        "scan scanme.nmap.org -p 20-100 --threads 50",
        "scan 127.0.0.1 -p 1-65535 --all-reports",
    )

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        if not context.args:
            if console and RICH_AVAILABLE:
                console.print("[bold red][!] Error: Target is required. Usage: scan <target> [options][/bold red]")
            else:
                print("[!] Error: Target is required. Usage: scan <target> [options]")
            return 1

        target = context.args[0]
        opts = context.options

        # Ports
        from portfootprint.scanner.port_parser import PortParser

        port_parser = PortParser()
        raw_ports = opts.get("ports") or opts.get("p")
        ports = port_parser.parse(raw_ports) if raw_ports else DEFAULT_PORTS_LIST

        threads = int(opts.get("threads") or opts.get("t") or DEFAULT_SCAN_THREADS)
        timeout = float(opts.get("timeout") or opts.get("w") or DEFAULT_SCAN_TIMEOUT)
        retries = int(opts.get("retries") or opts.get("r") or DEFAULT_SCAN_RETRIES)
        verbose = bool(opts.get("verbose") or opts.get("v") or False)

        all_reports = bool(opts.get("all_reports") or False)
        json_report = opts.get("json") or opts.get("json_report")
        csv_report = opts.get("csv") or opts.get("csv_report")
        html_report = opts.get("html") or opts.get("html_report")

        if all_reports:
            json_report = json_report or "report.json"
            csv_report = csv_report or "report.csv"
            html_report = html_report or "report.html"

        config = ScanConfiguration(
            target=target,
            ports=ports,
            threads=threads,
            timeout=timeout,
            retries=retries,
            verbose=verbose,
            json_report=json_report,
            csv_report=csv_report,
            html_report=html_report,
            all_reports=all_reports,
            log_file=opts.get("log_file"),
        )

        try:
            manager = ScanManager(config)
            manager.execute()
            return 0
        except Exception as e:
            if console and RICH_AVAILABLE:
                console.print(f"[bold red][!] Scan failed: {e}[/bold red]")
            else:
                print(f"[!] Scan failed: {e}")
            return 1


class QuickCommand(BaseCommand):
    """Executes a quick top-ports scan on a target."""

    name = "quick"
    description = "Quickly scan the top common service ports on a target"
    syntax = "quick <target> [--all-reports]"
    aliases = ("q", "fast")
    examples = ("quick localhost", "quick scanme.nmap.org --all-reports")

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        if not context.args:
            if console and RICH_AVAILABLE:
                console.print("[bold red][!] Error: Target is required. Usage: quick <target>[/bold red]")
            else:
                print("[!] Error: Target is required. Usage: quick <target>")
            return 1

        target = context.args[0]
        all_reports = bool(context.options.get("all_reports", False))

        config = ScanConfiguration(
            target=target,
            ports=DEFAULT_PORTS_LIST,
            threads=30,
            timeout=1.5,
            retries=1,
            verbose=False,
            json_report="report.json" if all_reports else None,
            csv_report="report.csv" if all_reports else None,
            html_report="report.html" if all_reports else None,
            all_reports=all_reports,
        )

        try:
            manager = ScanManager(config)
            manager.execute()
            return 0
        except Exception as e:
            if console and RICH_AVAILABLE:
                console.print(f"[bold red][!] Quick scan failed: {e}[/bold red]")
            else:
                print(f"[!] Quick scan failed: {e}")
            return 1


class LocalCommand(BaseCommand):
    """Detects all open listening ports on the machine and fingerprints them automatically."""

    name = "local"
    description = "Auto-discover active listening ports on this machine and scan them"
    syntax = "local [--all-reports] [--html FILE]"
    aliases = ("listen", "mine")
    examples = ("local", "local --all-reports", "local --html local_ports.html")

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        from portfootprint.cli.doctor import DoctorDiagnostic

        if console and RICH_AVAILABLE:
            console.print("[cyan][*] Auto-detecting local listening ports...[/cyan]")
        else:
            print("[*] Auto-detecting local listening ports...")

        ports = DoctorDiagnostic.detect_local_listening_ports()
        if not ports:
            if console and RICH_AVAILABLE:
                console.print("[yellow][!] No active listening TCP ports detected on this machine.[/yellow]")
            else:
                print("[!] No active listening TCP ports detected on this machine.")
            return 0

        ports_str = ",".join(str(p) for p in ports)
        if console and RICH_AVAILABLE:
            console.print(
                f"[bold green][+] Detected {len(ports)} listening ports:[/bold green] [dim white]{ports_str}[/dim white]"
            )
            console.print("[cyan][*] Fingerprinting services on 127.0.0.1...[/cyan]\n")
        else:
            print(f"[+] Detected {len(ports)} listening ports: {ports_str}")
            print("[*] Fingerprinting services on 127.0.0.1...\n")

        all_reports = bool(context.options.get("all_reports", True))
        html_file = context.options.get("html") or context.options.get("html_report") or "local_open_ports.html"

        config = ScanConfiguration(
            target="127.0.0.1",
            ports=ports,
            threads=min(30, max(10, len(ports))),
            timeout=1.5,
            retries=1,
            verbose=False,
            json_report="report.json" if all_reports else None,
            csv_report="report.csv" if all_reports else None,
            html_report=html_file,
            all_reports=all_reports,
        )

        try:
            manager = ScanManager(config)
            manager.execute()
            return 0
        except Exception as e:
            if console and RICH_AVAILABLE:
                console.print(f"[bold red][!] Local scan failed: {e}[/bold red]")
            else:
                print(f"[!] Local scan failed: {e}")
            return 1


class HistoryCommand(BaseCommand):
    """Displays previous scan execution history."""

    name = "history"
    description = "View previous scan execution history and exported reports"
    syntax = "history"
    aliases = ("hist", "log")
    examples = ("history",)

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        from portfootprint.core.history import ScanHistoryManager

        hm = ScanHistoryManager()
        history = hm.get_history()

        if not history:
            if console and RICH_AVAILABLE:
                console.print("[dim white]No scan history records found.[/dim white]")
            else:
                print("No scan history records found.")
            return 0

        if console and RICH_AVAILABLE:
            table = Table(title="PortFootprint Scan History Index", border_style="cyan", show_header=True)
            table.add_column("Timestamp", style="dim white", width=20)
            table.add_column("Target", style="bold cyan", width=22)
            table.add_column("Open", style="bold green", width=8)
            table.add_column("Closed", style="dim red", width=8)
            table.add_column("Total", style="white", width=8)
            table.add_column("Saved Reports", style="dim cyan")

            for entry in history:
                ts = entry.get("timestamp", "N/A")
                target = entry.get("target", "N/A")
                s = entry.get("summary", {})
                reps = entry.get("reports", {})
                rep_links = []
                for k, v in reps.items():
                    if v:
                        rep_links.append(f"{k}: {os.path.basename(v)}")
                rep_str = ", ".join(rep_links) if rep_links else "None"

                table.add_row(
                    ts, target, str(s.get("open", 0)), str(s.get("closed", 0)), str(s.get("total_ports", 0)), rep_str
                )

            console.print(table)
            console.print(f"\n[dim white]Total saved scan records: {len(history)}[/dim white]\n")
        else:
            print("=" * 60)
            print("PortFootprint Scan History Index")
            print("=" * 60)
            for entry in history:
                s = entry.get("summary", {})
                print(f"[{entry.get('timestamp')}] Target: {entry.get('target')}")
                print(
                    f"  Summary: Total {s.get('total_ports', 0)} | Open {s.get('open', 0)} | Closed {s.get('closed', 0)}"
                )
            print("=" * 60)

        return 0


class CompareCommand(BaseCommand):
    """Compares two JSON scan reports to detect changes."""

    name = "compare"
    description = "Compare two JSON scan reports to discover newly opened/closed ports"
    syntax = "compare <old_report.json> <new_report.json>"
    aliases = ("diff",)
    examples = ("compare old_scan.json new_scan.json",)

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        if len(context.args) < 2:
            if console and RICH_AVAILABLE:
                console.print("[bold red][!] Usage: compare <old_report.json> <new_report.json>[/bold red]")
            else:
                print("[!] Usage: compare <old_report.json> <new_report.json>")
            return 1

        old_file, new_file = context.args[0], context.args[1]
        from portfootprint.cli.formatter import TerminalFormatter
        from portfootprint.core.comparison import ScanComparer

        try:
            comparer = ScanComparer()
            diff = comparer.compare_files(old_file, new_file)
            TerminalFormatter.print_comparison(diff)
            return 0
        except Exception as e:
            if console and RICH_AVAILABLE:
                console.print(f"[bold red][!] Comparison failed: {e}[/bold red]")
            else:
                print(f"[!] Comparison failed: {e}")
            return 1


class DoctorCommand(BaseCommand):
    """Runs environment, socket, and system health checks."""

    name = "doctor"
    description = "Run diagnostic health checks on networking and system components"
    syntax = "doctor"
    aliases = ("status", "check")
    examples = ("doctor",)

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        from portfootprint.cli.doctor import DoctorDiagnostic

        DoctorDiagnostic.run_diagnostics(console=console)
        return 0


class HelpCommand(BaseCommand):
    """Displays command help and usage."""

    name = "help"
    description = "List all available commands or view help for a specific command"
    syntax = "help [command]"
    aliases = ("?", "h")
    examples = ("help", "help scan", "help local", "help quick")

    def __init__(self, registry: dict[str, BaseCommand]) -> None:
        self.registry = registry

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        if context.args:
            target = context.args[0].lower()
            cmd = self.registry.get(target)
            if not cmd:
                for c in self.registry.values():
                    if target in c.aliases:
                        cmd = c
                        break

            if cmd:
                if console and RICH_AVAILABLE:
                    table = Table(title=f"Command Help: {cmd.name}", border_style="cyan", show_header=False)
                    table.add_column("Field", style="bold white", width=15)
                    table.add_column("Value", style="cyan")
                    table.add_row("Description", cmd.description)
                    table.add_row("Syntax", cmd.syntax)
                    if cmd.aliases:
                        table.add_row("Aliases", ", ".join(cmd.aliases))
                    if cmd.examples:
                        table.add_row("Examples", "\n".join(cmd.examples))
                    console.print(table)
                else:
                    print(f"Command: {cmd.name}")
                    print(f"Description: {cmd.description}")
                    print(f"Syntax: {cmd.syntax}")
                    if cmd.aliases:
                        print(f"Aliases: {', '.join(cmd.aliases)}")
                    if cmd.examples:
                        print("Examples:\n  " + "\n  ".join(cmd.examples))
                return 0

            if console and RICH_AVAILABLE:
                console.print(f"[bold red][!] Unknown command: '{target}'. Type 'help' for command list.[/bold red]")
            else:
                print(f"[!] Unknown command: '{target}'. Type 'help' for command list.")
            return 1

        # General help list
        if console and RICH_AVAILABLE:
            table = Table(title="PortFootprint Interactive Commands", border_style="cyan", show_header=True)
            table.add_column("Command", style="bold cyan", width=14)
            table.add_column("Description", style="white", width=42)
            table.add_column("Syntax", style="dim white")

            seen = set()
            for cmd in self.registry.values():
                if cmd.name in seen:
                    continue
                seen.add(cmd.name)
                table.add_row(cmd.name, cmd.description, cmd.syntax)

            console.print(table)
            console.print(
                '\n[dim white]Type "[bold cyan]help <command>[/bold cyan]" for syntax details & examples.[/dim white]\n'
            )
        else:
            print("=" * 60)
            print("PortFootprint Interactive Commands")
            print("=" * 60)
            seen = set()
            for cmd in self.registry.values():
                if cmd.name in seen:
                    continue
                seen.add(cmd.name)
                print(f"{cmd.name:12s} - {cmd.description}")
            print("=" * 60)

        return 0


class ClearCommand(BaseCommand):
    """Clears the terminal display."""

    name = "clear"
    description = "Clear the terminal display screen"
    syntax = "clear"
    aliases = ("cls",)
    examples = ("clear",)

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        if console and RICH_AVAILABLE:
            console.clear()
        else:
            sys.stdout.write("\033[H\033[2J")
            sys.stdout.flush()
        return 0


class VersionCommand(BaseCommand):
    """Displays framework release version."""

    name = "version"
    description = "Display PortFootprint framework version"
    syntax = "version"
    aliases = ("ver", "-V", "--version")
    examples = ("version",)

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        msg = f"PortFootprint Framework v{__version__}"
        if console and RICH_AVAILABLE:
            console.print(f"[bold green]{msg}[/bold green]")
        else:
            print(msg)
        return 0


class ExitCommand(BaseCommand):
    """Exits the interactive console."""

    name = "exit"
    description = "Exit the PortFootprint interactive console"
    syntax = "exit"
    aliases = ("quit", "q")
    examples = ("exit",)

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        if console and RICH_AVAILABLE:
            console.print("[dim white]Exiting PortFootprint console. Goodbye![/dim white]")
        else:
            print("Exiting PortFootprint console. Goodbye!")
        sys.exit(0)


def build_default_command_registry() -> dict[str, BaseCommand]:
    """Builds and returns the default command registry."""
    reg: dict[str, BaseCommand] = {
        "scan": ScanCommand(),
        "quick": QuickCommand(),
        "local": LocalCommand(),
        "history": HistoryCommand(),
        "compare": CompareCommand(),
        "doctor": DoctorCommand(),
        "clear": ClearCommand(),
        "version": VersionCommand(),
        "exit": ExitCommand(),
        "quit": ExitCommand(),
    }
    # Help command takes the registry
    reg["help"] = HelpCommand(reg)
    return reg
