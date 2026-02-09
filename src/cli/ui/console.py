"""CLI UI components."""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


def print_banner() -> None:
    """Print Minka banner."""
    banner = """
[bold cyan]    __  ___       __               [/bold cyan]
[bold cyan]   /  |/  /__  __/ /__  ___  ____  [/bold cyan]
[bold cyan]  / /|_/ / _ \/ / / _ \/ _ \/ __ \ [/bold cyan]
[bold cyan] / /  / /  __/ / /  __/  __/ /_/ / [/bold cyan]
[bold cyan]/_/  /_/\___/_/_/\___/\___/ .___/  [/bold cyan]
[bold cyan]                         /_/       [/bold cyan]
    
[cyan]Asistente Virtual de Ciberseguridad[/cyan]
[dim]Máster UCM - Ciberseguridad Defensiva y Ofensiva[/dim]
    """
    console.print(banner)


def print_welcome(agent_type: str) -> None:
    """Print welcome message.

    Args:
        agent_type: Type of agent being used
    """
    agent_names = {
        "vuln": "Investigador de Vulnerabilidades",
        "red": "Red Team",
        "blue": "Blue Team",
        "osint": "OSINT",
    }

    agent_name = agent_names.get(agent_type, "General")

    welcome_text = f"""
[bold green]¡Bienvenido a Minka![/bold green]

Estás usando el agente: [cyan]{agent_name}[/cyan]

Este es un proyecto educativo para el Máster en Ciberseguridad
de la Universidad Complutense de Madrid.

[bold yellow]Recordatorio:[/bold yellow] Usa este asistente solo para fines educativos
y en sistemas que te pertenezcan o tengas autorización expresa.
    """

    console.print(Panel(welcome_text, box=box.ROUNDED, border_style="cyan"))


def print_error(message: str) -> None:
    """Print error message.

    Args:
        message: Error message
    """
    console.print(f"[bold red]Error:[/bold red] {message}")


def print_success(message: str) -> None:
    """Print success message.

    Args:
        message: Success message
    """
    console.print(f"[bold green]✓[/bold green] {message}")


def print_info(message: str) -> None:
    """Print info message.

    Args:
        message: Info message
    """
    console.print(f"[cyan]ℹ[/cyan] {message}")
