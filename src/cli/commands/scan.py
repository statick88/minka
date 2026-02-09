"""Scan command for Minka CLI."""

import click
from rich.console import Console

console = Console()


@click.command()
@click.option("--target", "-t", required=True, help="Target to scan (URL, IP, domain)")
@click.option("--type", "scan_type", type=click.Choice(["web", "network", "port"]), default="web")
@click.option("--output", "-o", help="Output file")
def scan(target: str, scan_type: str, output: str | None) -> None:
    """Perform security scans."""
    console.print(f"[cyan]Scanning {target} ({scan_type})...[/cyan]")
    console.print("[yellow]Note: Full scanning functionality requires additional setup[/yellow]")
