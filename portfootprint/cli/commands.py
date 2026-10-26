"""
Command Definitions and Dispatcher for PortFootprint CLI Console.
Implements modular, user-friendly interactive commands.
"""

import json
import os
import shlex
import sys
import webbrowser
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    RICH_AVAILABLE: bool = True
else:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        RICH_AVAILABLE = True
    except ImportError:
        Console = None
        Panel = None
        Table = None
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


class ReportCommand(BaseCommand):
    """Explores, selects, and opens scan reports (HTML, JSON, CSV)."""

    name = "report"
    description = "Explore, select, and click/open reports (HTML, JSON, CSV, All)"
    syntax = "report [html|json|csv|all|open <file>]"
    aliases = ("reports", "rep")
    examples = (
        "report",
        "report html",
        "report json",
        "report csv",
        "report all",
        "report open report.html",
    )

    @staticmethod
    def _to_file_url(path: str) -> str:
        clean = os.path.abspath(path).replace("\\", "/")
        return f"file:///{clean}" if not clean.startswith("/") else f"file://{clean}"

    @classmethod
    def find_reports(cls) -> list[dict[str, str]]:
        """Scans workspace and history for existing report files."""
        candidates: list[dict[str, str]] = []
        seen_paths: set[str] = set()

        def add_file(fmt: str, p: str) -> None:
            if not p:
                return
            abs_p = os.path.abspath(p)
            norm_p = os.path.normcase(abs_p)
            if norm_p in seen_paths:
                return
            seen_paths.add(norm_p)
            if os.path.exists(abs_p):
                sz = os.path.getsize(abs_p)
                size_str = f"{sz / 1024:.1f} KB" if sz >= 1024 else f"{sz} B"
                candidates.append(
                    {
                        "format": fmt.lower(),
                        "path": p,
                        "abs_path": abs_p,
                        "size": size_str,
                        "url": cls._to_file_url(abs_p),
                    }
                )

        # Standard report filenames
        for fmt, name in [
            ("html", "report.html"),
            ("html", "local_open_ports.html"),
            ("html", "open_ports.html"),
            ("json", "report.json"),
            ("csv", "report.csv"),
        ]:
            if os.path.exists(name):
                add_file(fmt, name)

        # Scan history entries
        try:
            from portfootprint.core.history import ScanHistoryManager

            hm = ScanHistoryManager()
            for entry in hm.get_history():
                for fmt, path in entry.get("reports", {}).items():
                    if path and os.path.exists(path):
                        add_file(fmt, path)
        except Exception:
            pass

        return candidates

    def execute(self, context: CommandContext, console: Optional[Any] = None) -> int:
        args = context.args
        existing = self.find_reports()

        # Handle 'report open <file>'
        if args and args[0].lower() == "open" and len(args) > 1:
            target_file = args[1]
            if os.path.exists(target_file):
                file_url = self._to_file_url(target_file)
                if console and RICH_AVAILABLE:
                    console.print(
                        f"[bold green][+] Opening report:[/bold green] [underline cyan]{file_url}[/underline cyan]"
                    )
                else:
                    print(f"[+] Opening report: {file_url}")
                webbrowser.open(file_url)
                return 0
            if console and RICH_AVAILABLE:
                console.print(f"[bold red][!] File not found: {target_file}[/bold red]")
            else:
                print(f"[!] File not found: {target_file}")
            return 1

        # Render format catalog and existing report listings
        self._render_catalog(console)
        self._render_existing_reports(console, existing)

        # Dispatch if action argument passed directly
        action = args[0].lower() if args else None
        if action:
            return self._handle_selection(action, existing, console)

        # Interactive selection prompt
        if sys.stdin.isatty():
            try:
                if console and RICH_AVAILABLE:
                    console.print(
                        "[bold cyan]Select a report to open/preview ([white]1[/white]=HTML, [white]2[/white]=JSON, [white]3[/white]=CSV, [white]4[/white]=All, [white]open <file>[/white], or [white]q[/white] to return):[/bold cyan]"
                    )
                prompt_text = "report select > "
                choice = input(prompt_text).strip()
                if not choice or choice.lower() in ("q", "quit", "exit", "back"):
                    return 0
                if choice.lower().startswith("open "):
                    file_to_open = choice[5:].strip()
                    if os.path.exists(file_to_open):
                        url = self._to_file_url(file_to_open)
                        if console and RICH_AVAILABLE:
                            console.print(
                                f"[bold green][+] Opening:[/bold green] [underline cyan]{url}[/underline cyan]"
                            )
                        else:
                            print(f"[+] Opening: {url}")
                        webbrowser.open(url)
                        return 0
                    print(f"[!] File not found: {file_to_open}")
                    return 1
                return self._handle_selection(choice.lower(), existing, console)
            except (KeyboardInterrupt, EOFError):
                print()
                return 0

        return 0

    def _render_catalog(self, console: Optional[Any]) -> None:
        """Renders report format specifications table."""
        if console and RICH_AVAILABLE:
            tbl = Table(title="PortFootprint Report Formats & Selection Guide", border_style="cyan", show_header=True)
            tbl.add_column("Option", style="bold white", width=8)
            tbl.add_column("Format", style="bold green", width=18)
            tbl.add_column("File Ext", style="cyan", width=10)
            tbl.add_column("Key Capabilities & Interactive Features", style="white")
            tbl.add_column("CLI Scan Flag", style="dim cyan", width=16)

            tbl.add_row(
                "[1]",
                "HTML Dashboard",
                ".html",
                "Interactive responsive single-page web app with dark mode, live search filtering, summary cards, and collapsible certificate handshakes.",
                "--html FILE",
            )
            tbl.add_row(
                "[2]",
                "JSON Data",
                ".json",
                "Full structured schema with host results, services, ports, certificates, and scan metrics for APIs, automation, and diffs.",
                "--json FILE",
            )
            tbl.add_row(
                "[3]",
                "CSV Spreadsheet",
                ".csv",
                "Flattened spreadsheet listing (Port, State, Service, Version, Extra) ready for Excel, Google Sheets, and compliance archives.",
                "--csv FILE",
            )
            tbl.add_row(
                "[4]",
                "All Reports",
                "All (3)",
                "Generates HTML Dashboard, JSON, and CSV simultaneously in a single scan pass for complete audit coverage.",
                "--all-reports",
            )
            console.print(tbl)
            console.print()
        else:
            print("=================================================")
            print("PortFootprint Report Formats & Selection Guide")
            print("=================================================")
            print("[1] HTML Dashboard (.html)     - Interactive web report with dark mode & search filters")
            print("[2] JSON Data (.json)          - Machine-readable structured format for APIs and diffs")
            print("[3] CSV Spreadsheet (.csv)     - Flattened tabular spreadsheet for Excel and audits")
            print("[4] All Reports (All 3)        - Generates HTML, JSON, and CSV simultaneously")
            print("=================================================\n")

    def _render_existing_reports(self, console: Optional[Any], existing: list[dict[str, str]]) -> None:
        """Renders discovered report files with clickable links."""
        if not existing:
            msg = (
                "[dim white]No reports found on disk yet. Run '[bold green]local[/bold green]' or "
                "'[bold cyan]scan <target> --all-reports[/bold cyan]' to generate one.[/dim white]\n"
            )
            if console and RICH_AVAILABLE:
                console.print(msg)
            else:
                print("No reports found on disk yet. Run 'local' or 'scan <target> --all-reports' to generate one.\n")
            return

        if console and RICH_AVAILABLE:
            tbl = Table(title="Discovered Reports On Disk (Click to Open)", border_style="green", show_header=True)
            tbl.add_column("Key", style="bold white", width=6)
            tbl.add_column("Format", style="bold yellow", width=16)
            tbl.add_column("File Name", style="cyan", width=26)
            tbl.add_column("Size", style="dim white", width=10)
            tbl.add_column("Clickable File Link", style="dim cyan")

            badges = {
                "html": "[bold green]HTML Dashboard[/bold green]",
                "json": "[bold cyan]JSON Data[/bold cyan]",
                "csv": "[bold yellow]CSV Spreadsheet[/bold yellow]",
            }

            for idx, r in enumerate(existing, start=1):
                badge = badges.get(r["format"], r["format"].upper())
                file_name = os.path.basename(r["path"])
                link = f"[link={r['url']}][bold underline cyan]{r['url']}[/bold underline cyan][/link]"
                tbl.add_row(f"[{idx}]", badge, file_name, r["size"], link)

            panel = Panel(
                tbl,
                title="[bold green]✓ Generated Reports Available[/bold green]",
                subtitle="[dim white]Tip: Click or Ctrl+Click on any link above, or select by number below[/dim white]",
                border_style="green",
            )
            console.print(panel)
            console.print()
        else:
            print("=================================================")
            print("Discovered Reports On Disk")
            print("=================================================")
            for idx, r in enumerate(existing, start=1):
                print(f"[{idx}] {r['format'].upper()}: {r['path']} ({r['size']})")
                print(f"    Link: {r['url']}")
            print("=================================================\n")

    def _handle_selection(self, choice: str, existing: list[dict[str, str]], console: Optional[Any]) -> int:
        """Processes report selection choice."""
        if choice.isdigit():
            val = int(choice)
            if 1 <= val <= len(existing):
                selected = existing[val - 1]
                url = selected["url"]
                if console and RICH_AVAILABLE:
                    console.print(
                        f"[bold green][+] Opening {selected['format'].upper()} report:[/bold green] [underline cyan]{url}[/underline cyan]"
                    )
                else:
                    print(f"[+] Opening {selected['format'].upper()} report: {url}")
                webbrowser.open(url)
                return 0

        if choice in ("1", "html"):
            html_reports = [r for r in existing if r["format"] == "html"]
            if html_reports:
                target_url = html_reports[0]["url"]
                if console and RICH_AVAILABLE:
                    console.print(
                        f"[bold green][+] Launching HTML Dashboard in browser:[/bold green] [underline cyan]{target_url}[/underline cyan]"
                    )
                else:
                    print(f"[+] Launching HTML Dashboard in browser: {target_url}")
                webbrowser.open(target_url)
                return 0
            if console and RICH_AVAILABLE:
                console.print(
                    "[yellow][!] No HTML report found on disk. Run '[bold green]local[/bold green]' or "
                    "'[bold cyan]scan <target> --html report.html[/bold cyan]' first.[/yellow]"
                )
            else:
                print("[!] No HTML report found on disk. Run 'local' or 'scan <target> --html report.html' first.")
            return 0

        if choice in ("2", "json"):
            json_reports = [r for r in existing if r["format"] == "json"]
            if json_reports:
                selected = json_reports[0]
                if console and RICH_AVAILABLE:
                    console.print(
                        f"[bold green][+] Found JSON report:[/bold green] [underline cyan]{selected['url']}[/underline cyan]"
                    )
                else:
                    print(f"[+] Found JSON report: {selected['url']}")
                try:
                    with open(selected["abs_path"], encoding="utf-8") as f:
                        data = json.load(f)
                    summary = data.get("summary", {})
                    if console and RICH_AVAILABLE:
                        console.print(
                            f"[cyan]Target:[/cyan] {data.get('target')} | [green]Open:[/green] {summary.get('open')} | [red]Closed:[/red] {summary.get('closed')}"
                        )
                        console.print(f"[dim white]Full report: {selected['abs_path']}[/dim white]")
                    else:
                        print(
                            f"Target: {data.get('target')} | Open: {summary.get('open')} | Closed: {summary.get('closed')}"
                        )
                except Exception:
                    webbrowser.open(selected["url"])
                return 0
            if console and RICH_AVAILABLE:
                console.print(
                    "[yellow][!] No JSON report found on disk. Run '[bold cyan]scan <target> --json report.json[/bold cyan]' first.[/yellow]"
                )
            else:
                print("[!] No JSON report found on disk. Run 'scan <target> --json report.json' first.")
            return 0

        if choice in ("3", "csv"):
            csv_reports = [r for r in existing if r["format"] == "csv"]
            if csv_reports:
                selected = csv_reports[0]
                if console and RICH_AVAILABLE:
                    console.print(
                        f"[bold green][+] Found CSV report:[/bold green] [underline cyan]{selected['url']}[/underline cyan]"
                    )
                else:
                    print(f"[+] Found CSV report: {selected['url']}")
                try:
                    with open(selected["abs_path"], encoding="utf-8", errors="replace") as f:
                        lines = [line.strip() for line in f.readlines()[:10]]
                    if console and RICH_AVAILABLE and lines:
                        tbl = Table(title=f"CSV Preview: {os.path.basename(selected['path'])}", border_style="yellow")
                        headers = [h.strip() for h in lines[0].split(",")]
                        for h in headers:
                            tbl.add_column(h, style="cyan")
                        for line in lines[1:8]:
                            row = [col.strip() for col in line.split(",")]
                            while len(row) < len(headers):
                                row.append("")
                            tbl.add_row(*row[: len(headers)])
                        console.print(tbl)
                    else:
                        for line in lines[:8]:
                            print(line)
                except Exception:
                    webbrowser.open(selected["url"])
                return 0
            if console and RICH_AVAILABLE:
                console.print(
                    "[yellow][!] No CSV report found on disk. Run '[bold cyan]scan <target> --csv report.csv[/bold cyan]' first.[/yellow]"
                )
            else:
                print("[!] No CSV report found on disk. Run 'scan <target> --csv report.csv' first.")
            return 0

        if choice in ("4", "all"):
            if console and RICH_AVAILABLE:
                console.print("[bold green][+] All Reports Selected:[/bold green]")
                console.print("  • HTML Dashboard : [cyan]--html report.html[/cyan]")
                console.print("  • JSON Data      : [cyan]--json report.json[/cyan]")
                console.print("  • CSV Spreadsheet: [cyan]--csv report.csv[/cyan]")
                console.print(
                    "\n[dim white]To generate all formats at once, run: [bold cyan]scan <target> --all-reports[/bold cyan][/dim white]\n"
                )
            else:
                print("[+] All Reports Selected:")
                print("  • HTML Dashboard : --html report.html")
                print("  • JSON Data      : --json report.json")
                print("  • CSV Spreadsheet: --csv report.csv")
                print("\nTo generate all formats at once, run: scan <target> --all-reports\n")
            html_reports = [r for r in existing if r["format"] == "html"]
            if html_reports:
                webbrowser.open(html_reports[0]["url"])
            return 0

        if console and RICH_AVAILABLE:
            console.print(f"[bold red][!] Unknown report option: '{choice}'. Type '1', '2', '3', or '4'.[/bold red]")
        else:
            print(f"[!] Unknown report option: '{choice}'. Type '1', '2', '3', or '4'.")
        return 1


def build_default_command_registry() -> dict[str, BaseCommand]:
    """Builds and returns the default command registry."""
    reg: dict[str, BaseCommand] = {
        "scan": ScanCommand(),
        "quick": QuickCommand(),
        "local": LocalCommand(),
        "report": ReportCommand(),
        "reports": ReportCommand(),
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
