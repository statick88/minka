"""Minka CLI - Interfaz de línea de comandos."""

import asyncio
import sys
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent.parent))

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .commands import analyze, chat, lab, scan
from .ui.console import print_banner, print_welcome

console = Console()


@click.group()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Ruta al archivo de configuración",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Modo verbose (más información de debug)",
)
@click.pass_context
def cli(ctx: click.Context, config: str | None, verbose: bool) -> None:
    """Minka - Asistente Virtual de Ciberseguridad.

    Proyecto para el Máster en Ciberseguridad Defensiva y Ofensiva - UCM
    """
    # Ensure context object is a dict
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["verbose"] = verbose


@cli.command()
@click.option(
    "--agent",
    "-a",
    type=click.Choice(["vuln", "red", "blue", "osint"]),
    default="vuln",
    help="Tipo de agente a usar",
)
@click.option(
    "--model",
    "-m",
    default="gpt-4o",
    help="Modelo LLM a utilizar",
)
def start(agent: str, model: str) -> None:
    """Iniciar Minka en modo interactivo."""
    print_banner()
    print_welcome(agent)

    # Importar aquí para evitar import circular
    from .interactive import InteractiveMode

    try:
        interactive = InteractiveMode(agent_type=agent, model=model)
        asyncio.run(interactive.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]¡Hasta luego! 👋[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
def status() -> None:
    """Verificar estado de Minka y dependencias."""
    print_banner()

    from core.config import get_settings

    try:
        settings = get_settings()

        console.print("\n[bold cyan]Estado del Sistema:[/bold cyan]\n")

        # Check GitHub Token
        if settings.github_token:
            token_status = "[green]✓ Configurado[/green]"
        else:
            token_status = "[red]✗ No configurado[/red]"
        console.print(f"GitHub Token: {token_status}")

        # Check Model
        console.print(f"Modelo LLM: [cyan]{settings.copilot_model}[/cyan]")

        # Check Mode
        console.print(f"Modo: [cyan]{settings.minka_mode}[/cyan]")

        # Check Features
        console.print(f"\n[bold]Características:[/bold]")
        console.print(
            f"  Streaming: {'[green]✓[/green]' if settings.enable_streaming else '[red]✗[/red]'}"
        )
        console.print(
            f"  MCP Tools: {'[green]✓[/green]' if settings.enable_mcp_tools else '[red]✗[/red]'}"
        )
        console.print(
            f"  Laboratorios: {'[green]✓[/green]' if settings.enable_labs else '[red]✗[/red]'}"
        )

        console.print("\n[green]✓ Minka está listo para usar[/green]")

    except Exception as e:
        console.print(f"\n[red]✗ Error: {e}[/red]")
        console.print("\n[yellow]Asegúrate de configurar GITHUB_TOKEN en el archivo .env[/yellow]")


@cli.command()
def version() -> None:
    """Mostrar versión de Minka."""
    from core import __version__

    console.print(
        Panel(
            f"[bold cyan]Minka v{__version__}[/bold cyan]\n"
            "Asistente Virtual de Ciberseguridad\n"
            "Máster UCM - Ciberseguridad Defensiva y Ofensiva",
            title="Versión",
            border_style="cyan",
        )
    )


# Add subcommands
cli.add_command(scan)
cli.add_command(analyze)
cli.add_command(lab)
cli.add_command(chat)


def main() -> None:
    """Entry point for the CLI."""
    try:
        cli()
    except Exception as e:
        console.print(f"[red]Error fatal: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
