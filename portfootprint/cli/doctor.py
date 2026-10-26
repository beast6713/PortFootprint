"""
Health & Diagnostic Doctor for PortFootprint.
Validates socket subsystems, network capabilities, protocols registry, and reporting.
"""

import socket
import subprocess
import sys
from typing import Any, Optional

try:
    from rich.console import Console
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    Console = None  # type: ignore
    Table = None  # type: ignore
    RICH_AVAILABLE = False


class DoctorDiagnostic:
    """Runs environment, networking, and filesystem diagnostics for PortFootprint."""

    @classmethod
    def run_diagnostics(cls, console: Optional[Any] = None) -> tuple[str, list[dict[str, str]]]:
        """Runs all diagnostics checks and returns overall status ('READY', 'WARNING', 'FAIL')."""
        results: list[dict[str, str]] = []

        # 1. Python Runtime
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        results.append({"name": "Python Environment", "status": "PASS", "details": f"v{py_ver} ({sys.platform})"})

        # 2. TCP Socket Creation & Subsystem
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.close()
            results.append(
                {"name": "TCP Socket Subsystem", "status": "PASS", "details": "Standard user-space socket active"}
            )
        except Exception as e:
            results.append({"name": "TCP Socket Subsystem", "status": "FAIL", "details": f"Socket error: {e}"})

        # 3. Localhost & DNS Resolution
        try:
            addr = socket.gethostbyname("localhost")
            results.append(
                {"name": "DNS / Host Resolution", "status": "PASS", "details": f"localhost resolved to {addr}"}
            )
        except Exception as e:
            results.append({"name": "DNS / Host Resolution", "status": "WARN", "details": f"DNS warning: {e}"})

        # 4. Service Protocols Registry
        try:
            import portfootprint.services.protocols  # noqa: F401
            from portfootprint.services.registry import registry

            count = len(registry._entries)
            results.append(
                {
                    "name": "Protocol Fingerprinters",
                    "status": "PASS",
                    "details": f"{count} modules loaded (SSH, HTTP, DB, etc.)",
                }
            )
        except Exception as e:
            results.append({"name": "Protocol Fingerprinters", "status": "FAIL", "details": f"Registry error: {e}"})

        # 5. Local Listening Port Enumeration
        local_ports_found = cls.detect_local_listening_ports()
        if local_ports_found:
            results.append(
                {
                    "name": "Local Port Enumerator",
                    "status": "PASS",
                    "details": f"Detected {len(local_ports_found)} listening ports",
                }
            )
        else:
            results.append(
                {"name": "Local Port Enumerator", "status": "WARN", "details": "No active listening ports detected"}
            )

        # 6. Reporting Engines (JSON, CSV, HTML)
        try:
            from portfootprint.reports.registry import export_registry

            formats = export_registry.list_formats()
            results.append(
                {
                    "name": "Report Exporters",
                    "status": "PASS",
                    "details": f"{len(formats)} formats ({', '.join(formats).upper()}) available",
                }
            )
        except Exception as e:
            results.append({"name": "Report Exporters", "status": "FAIL", "details": f"Exporter error: {e}"})

        # 7. Scan History Manager
        try:
            from portfootprint.core.history import ScanHistoryManager

            hm = ScanHistoryManager()
            hist = hm.get_history()
            results.append(
                {"name": "Scan History DB", "status": "PASS", "details": f"{len(hist)} saved scans in history"}
            )
        except Exception as e:
            results.append({"name": "Scan History DB", "status": "WARN", "details": f"History warning: {e}"})

        # Determine overall status
        has_fail = any(r["status"] == "FAIL" for r in results)
        has_warn = any(r["status"] == "WARN" for r in results)

        if has_fail:
            overall = "ERROR"
        elif has_warn:
            overall = "WARNING"
        else:
            overall = "READY"

        if console:
            cls.render_results(console, overall, results)

        return overall, results

    @classmethod
    def detect_local_listening_ports(cls) -> list[int]:
        """Discovers local active listening ports using netstat or PowerShell."""
        ports = set()
        # Fast path 1: netstat -ano
        try:
            cmd = ["netstat", "-ano"] if sys.platform == "win32" else ["netstat", "-tuln"]
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if "LISTEN" in line.upper():
                    parts = line.split()
                    if len(parts) >= 2:
                        addr = parts[1]
                        port_str = addr.rsplit(":", 1)[-1]
                        if port_str.isdigit():
                            p = int(port_str)
                            if 1 <= p <= 65535:
                                ports.add(p)
        except Exception:
            pass

        # Fast path 2 fallback on Windows: PowerShell
        if not ports and sys.platform == "win32":
            try:
                ps_cmd = [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique",
                ]
                out = subprocess.check_output(ps_cmd, text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    clean = line.strip()
                    if clean.isdigit():
                        p = int(clean)
                        if 1 <= p <= 65535:
                            ports.add(p)
            except Exception:
                pass

        return sorted(ports)

    @classmethod
    def render_results(cls, console: Any, overall: str, results: list[dict[str, str]]) -> None:
        """Render diagnostic results to terminal using Rich or plain text."""
        if RICH_AVAILABLE and console:
            table = Table(title="PortFootprint System Diagnostics", border_style="cyan", show_header=True)
            table.add_column("Subsystem", style="bold white", width=25)
            table.add_column("Status", width=12)
            table.add_column("Diagnostics Detail", style="dim white")

            for r in results:
                st = r["status"]
                st_styled = (
                    "[bold green]PASS[/bold green]"
                    if st == "PASS"
                    else ("[bold yellow]WARN[/bold yellow]" if st == "WARN" else "[bold red]FAIL[/bold red]")
                )
                table.add_row(r["name"], st_styled, r["details"])

            console.print(table)
            status_color = (
                "bold green" if overall == "READY" else ("bold yellow" if overall == "WARNING" else "bold red")
            )
            console.print(f"\nOverall Diagnostic Status: [{status_color}]{overall}[/{status_color}]\n")
        else:
            print("=" * 60)
            print("PortFootprint System Diagnostics")
            print("=" * 60)
            for r in results:
                print(f"[{r['status']:4s}] {r['name']:25s} - {r['details']}")
            print("=" * 60)
            print(f"Overall Diagnostic Status: {overall}\n")
