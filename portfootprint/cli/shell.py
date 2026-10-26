"""
Interactive REPL Shell for PortFootprint.
Provides prompt_toolkit session with auto-completion, syntax highlighting, and history.
Falls back safely to standard input() if prompt_toolkit is unavailable.
"""

import sys
from typing import Any, Dict, Optional

try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    Console = None  # type: ignore
    RICH_AVAILABLE = False

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.styles import Style
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False

from portfootprint.cli.commands import BaseCommand, CommandContext, CommandParser


class PortFootprintShell:
    """Manages the interactive REPL shell session."""

    def __init__(self, registry: Dict[str, BaseCommand], console: Optional[Any] = None) -> None:
        self.registry = registry
        self.console = console or (Console() if RICH_AVAILABLE else None)

        if PROMPT_TOOLKIT_AVAILABLE:
            words = list(registry.keys()) + [
                "--ports", "-p", "--threads", "-t", "--timeout", "-w",
                "--all-reports", "--html", "--json", "--csv", "--verbose",
                "localhost", "127.0.0.1", "scanme.nmap.org"
            ]
            self.completer = WordCompleter(words, ignore_case=True)
            self.style = Style.from_dict({
                "prompt": "bold #00ffff",
                "arrow": "bold #ff00ff",
            })
            self.session = PromptSession(
                history=InMemoryHistory(),
                completer=self.completer,
                auto_suggest=AutoSuggestFromHistory(),
                style=self.style,
            )
        else:
            self.session = None

    def run_loop(self) -> int:
        """Runs the interactive command loop until user exits."""
        while True:
            try:
                if PROMPT_TOOLKIT_AVAILABLE and self.session:
                    prompt_msg = [
                        ("class:prompt", "portfootprint"),
                        ("class:arrow", " > "),
                    ]
                    user_input = self.session.prompt(prompt_msg)
                else:
                    user_input = input("portfootprint > ")

                clean = user_input.strip()
                if not clean:
                    continue

                ctx = CommandParser.parse(clean)
                cmd_obj = self.registry.get(ctx.command_name)
                if not cmd_obj:
                    # Check aliases
                    for c in self.registry.values():
                        if ctx.command_name in c.aliases:
                            cmd_obj = c
                            break

                if cmd_obj:
                    cmd_obj.execute(ctx, console=self.console)
                else:
                    msg = f"[bold red][!] Unknown command: '{ctx.command_name}'. Type 'help' for command list.[/bold red]" if (self.console and RICH_AVAILABLE) else f"[!] Unknown command: '{ctx.command_name}'. Type 'help' for command list."
                    if self.console and RICH_AVAILABLE:
                        self.console.print(msg)
                    else:
                        print(msg)

            except (KeyboardInterrupt, EOFError):
                if self.console and RICH_AVAILABLE:
                    self.console.print("\n[dim white]Interrupted. Type 'exit' to quit.[/dim white]")
                else:
                    print("\nInterrupted. Type 'exit' to quit.")
                continue
            except SystemExit:
                return 0
            except Exception as e:
                msg = f"[bold red][!] Runtime Error: {e}[/bold red]" if (self.console and RICH_AVAILABLE) else f"[!] Runtime Error: {e}"
                if self.console and RICH_AVAILABLE:
                    self.console.print(msg)
                else:
                    print(msg)

        return 0
