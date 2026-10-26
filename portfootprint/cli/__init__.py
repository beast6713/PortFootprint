"""
CLI parsing, interactive console, and representation modules for PortFootprint.
"""

from portfootprint.cli.banner import PortFootprintBanner
from portfootprint.cli.commands import BaseCommand, CommandContext, build_default_command_registry
from portfootprint.cli.console import PortFootprintConsole, launch_console
from portfootprint.cli.doctor import DoctorDiagnostic
from portfootprint.cli.formatter import TerminalFormatter
from portfootprint.cli.parser import CommandLineParser
from portfootprint.cli.progress import ConsoleProgressRenderer

__all__ = [
    "CommandLineParser",
    "TerminalFormatter",
    "ConsoleProgressRenderer",
    "PortFootprintConsole",
    "launch_console",
    "PortFootprintBanner",
    "DoctorDiagnostic",
    "BaseCommand",
    "CommandContext",
    "build_default_command_registry",
]
