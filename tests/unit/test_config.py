"""Tests for configuration."""

import pytest
from pydantic import ValidationError

from core.config import Settings, get_settings


class TestSettings:
    """Test settings validation."""

    def test_valid_settings(self):
        """Test valid settings creation."""
        settings = Settings(
            github_token="ghp_valid_token_12345",
            copilot_model="gpt-4o",
        )
        assert settings.github_token == "ghp_valid_token_12345"
        assert settings.copilot_model == "gpt-4o"
        assert settings.minka_mode == "research"

    def test_invalid_github_token_format(self):
        """Test invalid GitHub token format."""
        with pytest.raises(ValidationError):
            Settings(
                github_token="invalid_token",
                copilot_model="gpt-4o",
            )

    def test_missing_github_token(self):
        """Test missing GitHub token."""
        with pytest.raises(ValidationError):
            Settings(
                github_token="",
                copilot_model="gpt-4o",
            )

    def test_default_values(self):
        """Test default configuration values."""
        settings = Settings(
            github_token="ghp_valid_token_12345",
        )
        assert settings.copilot_model == "gpt-4o"
        assert settings.minka_mode == "research"
        assert settings.enable_streaming is True
        assert settings.enable_mcp_tools is True

    def test_is_development_property(self):
        """Test development mode property."""
        settings = Settings(
            github_token="ghp_valid_token_12345",
            minka_mode="research",
        )
        assert settings.is_development is True

        settings_production = Settings(
            github_token="ghp_valid_token_12345",
            minka_mode="production",
        )
        assert settings_production.is_development is False

    def test_is_safe_mode_property(self):
        """Test safe mode property."""
        settings = Settings(
            github_token="ghp_valid_token_12345",
            allow_dangerous_operations=False,
        )
        assert settings.is_safe_mode is True

        settings_unsafe = Settings(
            github_token="ghp_valid_token_12345",
            allow_dangerous_operations=True,
        )
        assert settings_unsafe.is_safe_mode is False


class TestGetSettings:
    """Test get_settings function."""

    def test_get_settings_returns_settings(self, monkeypatch):
        """Test get_settings returns Settings instance."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_valid_token_12345")
        settings = get_settings()
        assert isinstance(settings, Settings)
