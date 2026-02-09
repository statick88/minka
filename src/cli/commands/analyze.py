"""Analyze command for Minka CLI."""

import click
from rich.console import Console

console = Console()


@click.command()
@click.option("--target", "-t", required=True, help="Target to analyze (file, URL)")
@click.option(
    "--type", "analysis_type", type=click.Choice(["code", "web", "binary"]), default="code"
)
def analyze(target: str, analysis_type: str) -> None:
    """Analyze targets for vulnerabilities."""
    console.print(f"[cyan]Analyzing {target} ({analysis_type})...[/cyan]")
    console.print("[yellow]Note: Run 'minka start' for interactive analysis[/yellow]")
