"""
TerminalFormatter module rendering formatted tables, summary statistics, and comparisons.
"""

import os
from typing import Any

from portfootprint.core.models import ScanResult
from portfootprint.core.statistics import ScanStatistics
from portfootprint.core.version import __version__


class TerminalFormatter:
    """
    Formats scan results into readable ASCII layouts for terminal stdout.
    Handles statistics display and scan history comparison layouts.
    """

    @staticmethod
    def print_banner() -> None:
        """Renders the top startup banner."""
        print("=================================================")
        print(f"PortFootprint v{__version__}")
        print("=================================================")

    @classmethod
    def print_pre_scan(cls, target: str, resolved_ip: str, total_ports: int, threads: int) -> None:
        """Prints target configurations summary before scan starts."""
        print(f"Target          {target}")
        print(f"Resolved IP     {resolved_ip}")
        print(f"Scanning        {total_ports} Ports")
        print(f"Threads         {threads}")
        print("--------------------------------------------")

    @classmethod
    def print_scan_result(cls, scan_result: ScanResult, verbose: bool = False) -> None:
        """
        Prints the results of scanned ports, and renders runtime summary.
        If verbose is False, avoids printing thousands of CLOSED ports,
        but always prints open/filtered ports.
        """
        if not scan_result.hosts:
            print("No hosts scanned.")
            return

        host_res = scan_result.hosts[0]

        open_count = 0
        closed_count = 0
        filtered_count = 0
        unknown_count = 0

        # Print individual port outputs
        for result in host_res.ports:
            state = result.state.upper()
            if state == "OPEN":
                open_count += 1
                if result.service:
                    s = result.service
                    srv_name = s.service_name
                    srv_ver = s.version if s.version else ""
                    extra = ""
                    if s.title:
                        extra = f"Title: {s.title}"
                    elif s.certificate and s.certificate.get("issuer"):
                        # Shorten long issuer string for clean layout
                        issuer_val = s.certificate.get("issuer", "")
                        if "cn=" in issuer_val.lower():
                            for part in issuer_val.split(","):
                                if part.strip().lower().startswith("cn="):
                                    extra = f"Issuer: {part.split('=', 1)[1]}"
                                    break
                        if not extra:
                            extra = f"Issuer: {issuer_val[:30]}"

                    print(
                        f"{result.port}/tcp".ljust(15)
                        + "OPEN".ljust(10)
                        + f"{srv_name}".ljust(15)
                        + f"{srv_ver}".ljust(20)
                        + f"{extra}"
                    )
                else:
                    print(f"{result.port}/tcp".ljust(15) + "OPEN")
            elif state == "CLOSED":
                closed_count += 1
                if verbose or len(host_res.ports) <= 20:
                    print(f"{result.port}/tcp".ljust(15) + "CLOSED")
            elif state == "FILTERED":
                filtered_count += 1
                print(f"{result.port}/tcp".ljust(15) + "FILTERED")
            else:
                unknown_count += 1
                if verbose:
                    print(f"{result.port}/tcp".ljust(15) + f"UNKNOWN ({result.reason})")

        # If some closed ports were hidden, show note
        if not verbose and len(host_res.ports) > 20 and closed_count > 0:
            print(f"({closed_count} closed ports omitted from display list)")

        # Calculate statistics metrics
        stats = ScanStatistics.calculate(scan_result)

        print("--------------------------------------------")
        print("Summary")
        print(f"Open            {stats.open_count}")
        print(f"Closed          {stats.closed_count}")
        if stats.filtered_count > 0 or verbose:
            print(f"Filtered        {stats.filtered_count}")
        if stats.unknown_count > 0:
            print(f"Unknown         {stats.unknown_count}")

        print("--------------------------------------------")
        print("Performance Metrics")
        print(f"Scan Speed      {stats.scan_speed:.1f} ports/sec")
        print(f"Services Found  {stats.services_detected}")
        print(f"Top Protocol    {stats.most_common_protocol}")
        print(f"Duration        {scan_result.duration:.2f} sec")
        print("=================================================")

    @classmethod
    def print_rich_scan_result(cls, scan_result: ScanResult, verbose: bool = False, console: Any = None) -> None:
        """
        Renders scan results using Rich tables and colorful status badges.
        Falls back cleanly to standard output if Rich is unavailable.
        """
        try:
            from rich.console import Console
            from rich.table import Table
        except ImportError:
            cls.print_scan_result(scan_result, verbose=verbose)
            return

        c = console or Console()
        if not scan_result.hosts:
            c.print("[yellow]No hosts scanned.[/yellow]")
            return

        host_res = scan_result.hosts[0]
        table = Table(title=f"Port Scan Results: {scan_result.target} ({scan_result.resolved_ip})", border_style="cyan")
        table.add_column("Port", style="bold cyan", width=12)
        table.add_column("State", width=12)
        table.add_column("Service", style="bold yellow", width=18)
        table.add_column("Version", style="white", width=18)
        table.add_column("Service Details / Certificate", style="dim white")

        open_count = 0
        closed_count = 0
        filtered_count = 0

        for result in host_res.ports:
            state = result.state.upper()
            if state == "OPEN":
                open_count += 1
                state_styled = "[bold green]OPEN[/bold green]"
                srv_name = result.service.service_name if result.service else "Unknown"
                srv_ver = result.service.version or "" if result.service else ""
                extra = ""
                if result.service:
                    if result.service.title:
                        extra = f"Title: {result.service.title}"
                    elif result.service.certificate and result.service.certificate.get("issuer"):
                        extra = f"Issuer: {result.service.certificate.get('issuer', '')[:35]}"

                table.add_row(f"{result.port}/tcp", state_styled, srv_name, srv_ver, extra)

            elif state == "CLOSED":
                closed_count += 1
                if verbose or len(host_res.ports) <= 20:
                    table.add_row(f"{result.port}/tcp", "[dim red]CLOSED[/dim red]", "-", "-", "-")

            elif state == "FILTERED":
                filtered_count += 1
                table.add_row(f"{result.port}/tcp", "[bold yellow]FILTERED[/bold yellow]", "-", "-", "-")

        c.print(table)

        if not verbose and len(host_res.ports) > 20 and closed_count > 0:
            c.print(f"[dim white]({closed_count} closed ports omitted from display list)[/dim white]")

        # Summary Metrics
        stats = ScanStatistics.calculate(scan_result)
        summary_tbl = Table(title="Scan Summary & Performance", border_style="dim cyan", show_header=False)
        summary_tbl.add_column("Metric", style="bold white", width=22)
        summary_tbl.add_column("Value", style="cyan")

        summary_tbl.add_row("Open Ports", f"[bold green]{stats.open_count}[/bold green]")
        summary_tbl.add_row("Closed Ports", f"[dim]{stats.closed_count}[/dim]")
        if stats.filtered_count > 0 or verbose:
            summary_tbl.add_row("Filtered Ports", f"[yellow]{stats.filtered_count}[/yellow]")
        summary_tbl.add_row("Scan Speed", f"{stats.scan_speed:.1f} ports/sec")
        summary_tbl.add_row("Services Detected", f"{stats.services_detected}")
        summary_tbl.add_row("Top Protocol", f"{stats.most_common_protocol}")
        summary_tbl.add_row("Scan Duration", f"{scan_result.duration:.2f} seconds")

        c.print(summary_tbl)
        c.print()

    @classmethod
    def print_reports_section(cls, reports: dict[str, str], console: Any = None) -> None:
        """
        Renders a dedicated, styled Generated Reports section with clickable links and file metadata.
        Falls back cleanly to plain text if Rich is unavailable.
        """
        active_reports = {k: v for k, v in reports.items() if v}
        if not active_reports:
            return

        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
        except ImportError:
            print("\n=================================================")
            print("Generated Scan Reports")
            print("=================================================")
            for fmt, path in active_reports.items():
                abs_p = os.path.abspath(path)
                size_str = ""
                if os.path.exists(abs_p):
                    sz = os.path.getsize(abs_p)
                    size_str = f" ({sz / 1024:.1f} KB)"
                file_url = f"file:///{abs_p.replace(os.sep, '/')}"
                print(f"[{fmt.upper()}] {path}{size_str}")
                print(f"  Clickable Link: {file_url}")
            print("=================================================\n")
            return

        c = console or Console()
        table = Table(border_style="green", show_header=True, header_style="bold green")
        table.add_column("Report Type", style="bold white", width=18)
        table.add_column("File Destination", style="cyan", width=26)
        table.add_column("Size", style="dim white", width=12)
        table.add_column("Clickable File Link / Status", style="dim cyan")

        format_badges = {
            "html": "[bold green]HTML Dashboard[/bold green]",
            "json": "[bold cyan]JSON Structured[/bold cyan]",
            "csv": "[bold yellow]CSV Spreadsheet[/bold yellow]",
        }

        for fmt, path in active_reports.items():
            abs_p = os.path.abspath(path)
            badge = format_badges.get(fmt.lower(), f"[bold white]{fmt.upper()}[/bold white]")
            file_name = os.path.basename(path)

            size_display = "N/A"
            if os.path.exists(abs_p):
                sz = os.path.getsize(abs_p)
                size_display = f"{sz / 1024:.1f} KB" if sz >= 1024 else f"{sz} B"

            clean_abs = abs_p.replace("\\", "/")
            file_url = f"file:///{clean_abs}" if not clean_abs.startswith("/") else f"file://{clean_abs}"
            link_markup = f"[link={file_url}][bold underline cyan]{file_url}[/bold underline cyan][/link]"
            table.add_row(badge, file_name, size_display, link_markup)

        panel = Panel(
            table,
            title="[bold green]✓ Generated Reports[/bold green]",
            subtitle="[dim white]Tip: Click or Ctrl+Click on any link above to open directly in your browser or editor[/dim white]",
            border_style="green",
        )
        c.print(panel)
        c.print()

    @classmethod
    def print_comparison(cls, diff: dict[str, Any]) -> None:
        """Renders the differences comparison table between two scan runs."""
        print("=================================================")
        print("Scan Comparison Report")
        print(f"Old Target:      {diff['old_target']}")
        print(f"New Target:      {diff['new_target']}")
        print("=================================================")

        # New open ports
        if diff["added"]:
            print("\n[+] Newly Open Ports:")
            for p in diff["added"]:
                print(f"  {p['port']}/tcp".ljust(15) + f"{p['service_name']}".ljust(15) + f"{p['version']}")

        # Closed ports
        if diff["removed"]:
            print("\n[-] Closed / Removed Ports:")
            for p in diff["removed"]:
                print(f"  {p['port']}/tcp".ljust(15) + f"{p['service_name']}".ljust(15) + f"{p['version']}")

        # Service version updates
        if diff["changed"]:
            print("\n[*] Modified / Updated Services:")
            for p in diff["changed"]:
                print(f"  Port {p['port']}/tcp:")
                print(f"    Old Service: {p['old_service']} {p['old_version']}")
                print(f"    New Service: {p['new_service']} {p['new_version']}")

        if not diff["added"] and not diff["removed"] and not diff["changed"]:
            print("\nNo differences detected between the two scans.")
        print("=================================================")
