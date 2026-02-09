"""Tests for vulnerability researcher agent."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from skills.vuln_researcher import VulnResearcherAgent


@pytest.fixture
def mock_client():
    """Create mock Minka client."""
    client = MagicMock()
    client.create_session = AsyncMock()
    client.send_message = AsyncMock(return_value="Test response")
    return client


@pytest.fixture
def agent(mock_client):
    """Create VulnResearcherAgent instance."""
    return VulnResearcherAgent(mock_client)


@pytest.mark.asyncio
async def test_agent_initialization(agent, mock_client):
    """Test agent initialization."""
    assert agent.client == mock_client
    assert agent.session is None
    assert "search_cve" in agent.tools
    assert "generate_poc_template" in agent.tools


@pytest.mark.asyncio
async def test_create_session(agent, mock_client):
    """Test session creation."""
    mock_session = MagicMock()
    mock_client.create_session.return_value = mock_session

    await agent.create_session()

    assert agent.session == mock_session
    mock_client.create_session.assert_called_once()

    # Verify system prompt is passed
    call_args = mock_client.create_session.call_args[1]
    assert "system_prompt" in call_args
    assert "vulnerabilidades" in call_args["system_prompt"].lower()


@pytest.mark.asyncio
async def test_process_message(agent, mock_client):
    """Test processing user message."""
    mock_client.send_message.return_value = "Analysis complete"

    # Create session first
    mock_session = MagicMock()
    mock_client.create_session.return_value = mock_session
    await agent.create_session()

    response = await agent.process("Analyze this code")
    assert response == "Analysis complete"


@pytest.mark.asyncio
async def test_process_without_session(agent):
    """Test processing without active session."""
    with pytest.raises(RuntimeError, match="Session not created"):
        await agent.process("Hello")


class TestCVESearch:
    """Test CVE search functionality."""

    @pytest.mark.asyncio
    async def test_search_cve_success(self, agent):
        """Test successful CVE search."""
        with patch("skills.vuln_researcher.httpx.AsyncClient") as mock_http:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2021-44228",
                            "descriptions": [{"value": "Log4j vulnerability"}],
                            "metrics": {
                                "cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]
                            },
                            "published": "2021-12-10",
                            "lastModified": "2022-01-01",
                        }
                    }
                ]
            }
            mock_response.raise_for_status = MagicMock()

            mock_client = MagicMock()
            mock_client.get = MagicMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_http.return_value = mock_client

            result = await agent._search_cve("CVE-2021-44228")

            assert result["id"] == "CVE-2021-44228"
            assert result["severity"] == "CRITICAL"


class TestPoCGeneration:
    """Test PoC template generation."""

    @pytest.mark.asyncio
    async def test_generate_sqli_poc(self, agent):
        """Test SQL injection PoC generation."""
        result = await agent._generate_poc_template("sqli", "python")

        assert result["vulnerability"] == "sqli"
        assert result["language"] == "python"
        assert "PoC educativo" in result["template"]
        assert "python" in result["template"].lower()

    @pytest.mark.asyncio
    async def test_generate_xss_poc(self, agent):
        """Test XSS PoC generation."""
        result = await agent._generate_poc_template("xss", "python")

        assert result["vulnerability"] == "xss"
        assert "<script>" in result["template"]

    @pytest.mark.asyncio
    async def test_generate_buffer_overflow_poc(self, agent):
        """Test Buffer Overflow PoC generation."""
        result = await agent._generate_poc_template("buffer_overflow", "c")

        assert result["vulnerability"] == "buffer_overflow"
        assert result["language"] == "c"
        assert "strcpy" in result["template"]

    @pytest.mark.asyncio
    async def test_generate_unknown_vulnerability(self, agent):
        """Test PoC generation for unknown vulnerability."""
        result = await agent._generate_poc_template("unknown", "python")

        assert "Template no disponible" in result["template"]
