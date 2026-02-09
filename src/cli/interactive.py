"""Interactive mode for Minka CLI."""

import asyncio
from typing import Optional

import structlog
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from core.client import MinkaClient
from core.config import get_settings
from skills.vuln_researcher import VulnResearcherAgent

logger = structlog.get_logger(__name__)
console = Console()

# Custom style for prompt
custom_style = Style.from_dict(
    {
        "prompt": "#00aa00 bold",
        "command": "#00aaaa",
    }
)


class InteractiveMode:
    """Interactive chat mode for Minka."""

    def __init__(self, agent_type: str = "vuln", model: str = "gpt-4o") -> None:
        """Initialize interactive mode.

        Args:
            agent_type: Type of agent (vuln, red, blue, osint)
            model: LLM model to use
        """
        self.agent_type = agent_type
        self.model = model
        self.client: Optional[MinkaClient] = None
        self.agent = None
        self.session = None

        # Setup prompt session with history
        history = FileHistory("/tmp/minka_history")
        self.prompt_session = PromptSession(
            history=history,
            auto_suggest=AutoSuggestFromHistory(),
            style=custom_style,
        )

    async def run(self) -> None:
        """Run the interactive loop."""
        try:
            # Initialize client
            console.print("[dim]Inicializando Minka...[/dim]")
            self.client = MinkaClient()
            await self.client.initialize()

            # Create agent based on type
            if self.agent_type == "vuln":
                self.agent = VulnResearcherAgent(self.client)
            else:
                self.agent = VulnResearcherAgent(self.client)  # Default

            # Create session
            await self.agent.create_session()

            console.print("[green]✓ Minka listo![/green]\n")
            console.print("[dim]Escribe 'help' para ver comandos, 'exit' para salir.[/dim]\n")

            # Main loop
            while True:
                try:
                    # Get user input
                    user_input = await self.prompt_session.prompt_async(
                        [("class:prompt", "minka> ")],
                    )

                    user_input = user_input.strip()
                    if not user_input:
                        continue

                    # Handle commands
                    if user_input.lower() in ("exit", "quit", "q"):
                        console.print("[yellow]¡Hasta luego! 👋[/yellow]")
                        break

                    if user_input.lower() == "help":
                        self._print_help()
                        continue

                    if user_input.lower() == "clear":
                        console.clear()
                        continue

                    # Process message with agent
                    with console.status("[cyan]Pensando...[/cyan]"):
                        response = await self.agent.process(user_input)

                    # Display response
                    self._display_response(response)

                except KeyboardInterrupt:
                    continue
                except EOFError:
                    break

        finally:
            if self.client:
                await self.client.close()

    def _print_help(self) -> None:
        """Print help information."""
        help_text = """
[bold cyan]Comandos disponibles:[/bold cyan]

[green]help[/green]     - Muestra esta ayuda
[green]clear[/green]    - Limpia la pantalla
[green]exit[/green]     - Salir de Minka

[bold cyan]Ejemplos de uso:[/bold cyan]

• "Analiza este código Python en busca de vulnerabilidades"
• "Busca CVEs relacionados con Log4j"
• "Genera un script Nmap para escanear puertos comunes"
• "Explica cómo funciona un buffer overflow"
• "Crea un PoC para SQL injection"

[bold yellow]Nota:[/bold yellow] Minka está en modo investigación.
Todo el output es para fines educativos.
        """
        console.print(Panel(help_text, title="Ayuda", border_style="cyan"))

    def _display_response(self, response: str) -> None:
        """Display the agent response.

        Args:
            response: Response text to display
        """
        # Try to render as markdown if it contains markdown syntax
        if any(marker in response for marker in ["```", "**", "#", "- "]):
            console.print(Markdown(response))
        else:
            console.print(response)

        console.print()  # Empty line for readability
