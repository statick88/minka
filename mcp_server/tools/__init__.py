"""
Minka MCP Tools Package

Herramientas MCP para GitHub Copilot SDK:

- experts: Biblioteca de investigadores
- ai_security: IA aplicada a ciberseguridad
- cases: Casos de estudio
- quotes: Citas estilo Mitnick
- narrative: Generador de narrativas
- vulnerabilities: CVEs y vulnerabilidades
- ucm_curriculum: Curriculum del Master UCM
- clean_architecture: Principios de Robert C. Martin
"""

from .experts import search_experts, get_citation
from .ai_security import search_ai_security, get_ai_paper
from .cases import get_case_study
from .quotes import get_quote
from .narrative import generate_narrative
from .vulnerabilities import get_cve_info, search_vulnerabilities
from .ucm_curriculum import get_ucm_module, get_all_modules
from .clean_architecture import get_clean_arch_info

__all__ = [
    "search_experts",
    "get_citation",
    "search_ai_security",
    "get_ai_paper",
    "get_case_study",
    "get_quote",
    "generate_narrative",
    "get_cve_info",
    "search_vulnerabilities",
    "get_ucm_module",
    "get_all_modules",
    "get_clean_arch_info",
]
