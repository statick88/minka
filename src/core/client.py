"""GitHub Copilot SDK Client wrapper for Minka."""

import asyncio
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional

import structlog
from copilot import CopilotClient, define_tool
from rich.console import Console

from .config import Settings, get_settings

logger = structlog.get_logger(__name__)
console = Console()


class MinkaClient:
    """Wrapper for GitHub Copilot SDK client.

    This class provides a simplified interface to interact with
    GitHub Copilot's agentic capabilities.
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        """Initialize the Minka client.

        Args:
            settings: Application settings. If None, uses default settings.
        """
        self.settings = settings or get_settings()
        self._client: Optional[CopilotClient] = None
        self._session: Optional[Any] = None
        self._tools: Dict[str, Callable] = {}
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the Copilot client and authenticate."""
        if self._initialized:
            return

        try:
            logger.info("Initializing Copilot client")

            # Create Copilot client
            self._client = CopilotClient()

            # Start the client (this handles authentication)
            await self._client.start()

            logger.info("Copilot client initialized successfully")
            self._initialized = True

        except Exception as e:
            logger.error("Failed to initialize Copilot client", error=str(e))
            raise RuntimeError(f"Failed to initialize Copilot: {e}") from e

    async def create_session(
        self,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        streaming: bool = True,
    ) -> Any:
        """Create a new Copilot session.

        Args:
            model: Model to use (defaults to settings.copilot_model)
            system_prompt: System prompt for the session
            tools: List of tools to register
            streaming: Enable streaming responses

        Returns:
            Session object
        """
        if not self._initialized:
            await self.initialize()

        model = model or self.settings.copilot_model

        session_config = {
            "model": model,
            "streaming": streaming,
        }

        if system_prompt:
            session_config["system_prompt"] = system_prompt

        if tools:
            session_config["tools"] = tools

        try:
            logger.info("Creating Copilot session", model=model)
            self._session = await self._client.create_session(session_config)
            return self._session

        except Exception as e:
            logger.error("Failed to create session", error=str(e))
            raise RuntimeError(f"Failed to create session: {e}") from e

    async def send_message(
        self,
        prompt: str,
        stream: bool = True,
        callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Send a message to Copilot.

        Args:
            prompt: User prompt
            stream: Whether to stream the response
            callback: Optional callback for streaming tokens

        Returns:
            Complete response text
        """
        if not self._session:
            raise RuntimeError("No active session. Call create_session() first.")

        try:
            if stream and self.settings.enable_streaming:
                return await self._send_streaming(prompt, callback)
            else:
                return await self._send_blocking(prompt)

        except Exception as e:
            logger.error("Failed to send message", error=str(e))
            raise RuntimeError(f"Failed to send message: {e}") from e

    async def _send_streaming(
        self,
        prompt: str,
        callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Send message with streaming response."""
        response_parts = []

        async for token in self._session.send_streaming({"prompt": prompt}):
            token_text = token.get("content", "")
            response_parts.append(token_text)

            if callback:
                callback(token_text)
            else:
                console.print(token_text, end="")

        return "".join(response_parts)

    async def _send_blocking(self, prompt: str) -> str:
        """Send message and wait for complete response."""
        response = await self._session.send_and_wait({"prompt": prompt})
        return response.get("content", "")

    def register_tool(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        handler: Callable,
    ) -> None:
        """Register a custom tool for Copilot to use.

        Args:
            name: Tool name
            description: Tool description
            parameters: JSON schema for parameters
            handler: Function to handle tool calls
        """
        tool = define_tool(
            name,
            {
                "description": description,
                "parameters": parameters,
            },
        )

        self._tools[name] = handler
        logger.info("Registered tool", name=name)

    async def execute_tool(self, name: str, params: Dict[str, Any]) -> Any:
        """Execute a registered tool.

        Args:
            name: Tool name
            params: Tool parameters

        Returns:
            Tool execution result
        """
        if name not in self._tools:
            raise ValueError(f"Tool '{name}' not registered")

        handler = self._tools[name]

        # Handle both sync and async handlers
        if asyncio.iscoroutinefunction(handler):
            return await handler(**params)
        else:
            return handler(**params)

    async def close(self) -> None:
        """Close the client and cleanup resources."""
        if self._client:
            try:
                await self._client.stop()
                logger.info("Copilot client closed")
            except Exception as e:
                logger.warning("Error closing client", error=str(e))
            finally:
                self._initialized = False

    async def __aenter__(self) -> "MinkaClient":
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()


@asynccontextmanager
async def get_copilot_client() -> AsyncGenerator[MinkaClient, None]:
    """Get a managed Copilot client instance.

    Usage:
        async with get_copilot_client() as client:
            session = await client.create_session()
            response = await client.send_message("Hello")
    """
    client = MinkaClient()
    try:
        yield client
    finally:
        await client.close()
