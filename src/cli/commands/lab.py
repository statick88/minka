"""Lab command for Minka CLI."""

import click
from rich.console import Console

console = Console()


@click.group()
def lab() -> None:
    """Manage vulnerable labs."""
    pass


@lab.command()
@click.argument("name")
def start(name: str) -> None:
    """Start a vulnerable lab."""
    labs = {
        "dvwa": "http://localhost:8081",
        "juice-shop": "http://localhost:8082",
        "webgoat": "http://localhost:8083",
    }

    if name in labs:
        console.print(f"[green]Starting {name}...[/green]")
        console.print(f"Access at: {labs[name]}")
        console.print("[yellow]Run: docker-compose --profile labs up -d[/yellow]")
    else:
        console.print(f"[red]Lab '{name}' not found. Available: {', '.join(labs.keys())}[/red]")


@lab.command()
def list() -> None:
    """List available labs."""
    console.print("[bold cyan]Available Labs:[/bold cyan]\n")
    console.print("  • dvwa        - Damn Vulnerable Web Application")
    console.print("  • juice-shop  - OWASP Juice Shop")
    console.print("  • webgoat     - OWASP WebGoat")
