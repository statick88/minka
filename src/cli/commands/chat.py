"""Chat command for Minka CLI."""

import click
from rich.console import Console

console = Console()


@click.command()
def chat() -> None:
    """Start interactive chat (alias for 'minka start')."""
    console.print("[cyan]Use 'minka start' to begin interactive mode[/cyan]")
