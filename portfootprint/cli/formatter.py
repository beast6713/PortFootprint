"""
TerminalFormatter module rendering formatted tables, summary statistics, and comparisons.
"""

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
                        f"{result.port}/tcp".ljust(15) +
                        "OPEN".ljust(10) +
                        f"{srv_name}".ljust(15) +
                        f"{srv_ver}".ljust(20) +
                        f"{extra}"
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
