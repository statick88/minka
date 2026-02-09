"""Configuration management for Minka."""

import os
from functools import lru_cache
from typing import Literal, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # GitHub Configuration
    github_token: str = Field(..., description="GitHub personal access token")
    copilot_model: str = Field(default="gpt-4o", description="Default Copilot model")
    copilot_session_timeout: int = Field(default=3600, description="Session timeout in seconds")

    # Application Mode
    minka_mode: Literal["research", "training", "production"] = Field(
        default="research",
        description="Minka operating mode",
    )
    minka_log_level: str = Field(default="INFO", description="Logging level")

    # Database
    database_url: str = Field(
        default="postgresql://minka:minka@localhost:5432/minka",
        description="Database connection URL",
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )

    # Feature Flags
    enable_streaming: bool = Field(default=True, description="Enable streaming responses")
    enable_mcp_tools: bool = Field(default=True, description="Enable MCP tools")
    enable_labs: bool = Field(default=True, description="Enable lab integration")
    enable_telemetry: bool = Field(default=False, description="Enable anonymous telemetry")

    # Security Settings
    max_tool_execution_time: int = Field(
        default=300, description="Max tool execution time (seconds)"
    )
    allow_dangerous_operations: bool = Field(
        default=False, description="Allow dangerous operations"
    )
    sandbox_level: Literal["strict", "moderate", "permissive"] = Field(
        default="strict",
        description="Sandbox security level",
    )

    # External APIs (Optional)
    virustotal_api_key: Optional[str] = Field(default=None, description="VirusTotal API key")
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API key")
    hibp_api_key: Optional[str] = Field(default=None, description="HaveIBeenPwned API key")
    nvd_api_key: Optional[str] = Field(default=None, description="NVD API key")

    @field_validator("github_token")
    @classmethod
    def validate_github_token(cls, v: str) -> str:
        """Validate GitHub token format."""
        if not v or v == "ghp_your_token_here":
            raise ValueError("GitHub token must be set to a valid value")
        if not v.startswith(("ghp_", "github_pat_")):
            raise ValueError("Invalid GitHub token format")
        return v

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.minka_mode == "research"

    @property
    def is_safe_mode(self) -> bool:
        """Check if running in safe mode."""
        return not self.allow_dangerous_operations


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
