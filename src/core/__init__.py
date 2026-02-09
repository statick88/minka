"""Minka Core Module.

Este módulo contiene la funcionalidad central del asistente,
incluyendo la integración con GitHub Copilot SDK.
"""

__version__ = "0.1.0"
__author__ = "UCM Cybersecurity Master"

from .client import MinkaClient
from .config import Settings, get_settings
from .session import SessionManager

__all__ = ["MinkaClient", "Settings", "get_settings", "SessionManager"]
