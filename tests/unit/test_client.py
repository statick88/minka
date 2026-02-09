"""Tests for Minka core client."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.client import MinkaClient
from core.config import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    return Settings(
        github_token="ghp_test_token_12345",
        copilot_model="gpt-4o",
        minka_mode="research",
    )


@pytest.fixture
def client(mock_settings):
    """Create Minka client instance."""
    return MinkaClient(settings=mock_settings)


@pytest.mark.asyncio
async def test_client_initialization(client):
    """Test client initialization."""
    assert client.settings is not None
    assert client._client is None
    assert client._session is None
    assert not client._initialized


@pytest.mark.asyncio
async def test_client_initialize_success(client):
    """Test successful client initialization."""
    with patch("core.client.CopilotClient") as mock_copilot:
        mock_instance = AsyncMock()
        mock_copilot.return_value = mock_instance

        await client.initialize()

        assert client._initialized
        mock_instance.start.assert_called_once()


@pytest.mark.asyncio
async def test_client_initialize_failure(client):
    """Test client initialization failure."""
    with patch("core.client.CopilotClient") as mock_copilot:
        mock_instance = AsyncMock()
        mock_instance.start.side_effect = Exception("Auth failed")
        mock_copilot.return_value = mock_instance

        with pytest.raises(RuntimeError, match="Failed to initialize Copilot"):
            await client.initialize()


@pytest.mark.asyncio
async def test_create_session(client):
    """Test session creation."""
    with patch("core.client.CopilotClient") as mock_copilot:
        mock_instance = AsyncMock()
        mock_session = MagicMock()
        mock_instance.create_session.return_value = mock_session
        mock_copilot.return_value = mock_instance

        await client.initialize()
        session = await client.create_session(
            model="gpt-4o",
            system_prompt="Test prompt",
        )

        assert session is not None
        mock_instance.create_session.assert_called_once()


@pytest.mark.asyncio
async def test_send_message_without_session(client):
    """Test sending message without active session."""
    with pytest.raises(RuntimeError, match="No active session"):
        await client.send_message("Hello")


@pytest.mark.asyncio
async def test_client_close(client):
    """Test client cleanup."""
    with patch("core.client.CopilotClient") as mock_copilot:
        mock_instance = AsyncMock()
        mock_copilot.return_value = mock_instance

        await client.initialize()
        await client.close()

        mock_instance.stop.assert_called_once()
        assert not client._initialized


class TestMinkaClientContextManager:
    """Test context manager functionality."""

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        """Test async context manager."""
        with patch("core.client.CopilotClient") as mock_copilot:
            mock_instance = AsyncMock()
            mock_copilot.return_value = mock_instance

            async with MinkaClient() as client:
                assert client._initialized

            mock_instance.stop.assert_called_once()
