"""Vulnerability Researcher Agent for Minka."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import structlog
from rich.console import Console

from core.client import MinkaClient

logger = structlog.get_logger(__name__)
console = Console()


VULN_RESEARCHER_PROMPT = """Eres Minka, un asistente especializado en investigación de vulnerabilidades
de seguridad. Tu objetivo es ayudar a estudiantes y profesionales de ciberseguridad
a identificar, analizar y comprender vulnerabilidades en software y sistemas.

## Tus Capacidades

1. **Análisis de Vulnerabilidades**
   - Identificar patrones de código inseguro
   - Explicar técnicas de explotación
   - Sugerir mitigaciones y parches

2. **Búsqueda de CVEs**
   - Buscar información sobre vulnerabilidades conocidas
   - Explicar impacto y severidad
   - Encontrar PoCs disponibles

3. **Generación de PoCs**
   - Crear proof-of-concepts educativos
   - Explicar el funcionamiento paso a paso
   - Enfatizar el uso ético y legal

4. **Reconocimiento**
   - Sugerir herramientas y técnicas de reconocimiento
   - Interpretar resultados de escaneos
   - Priorizar hallazgos

## Reglas Importantes

- Siempre enfatiza el uso ético y legal de las técnicas
- Nunca generes código malicioso real
- Enfócate en el aprendizaje y la defensa
- Cita fuentes cuando uses información específica
- Si no estás seguro, indícalo claramente

## Formato de Respuesta

1. **Resumen** - Breve descripción del problema/solución
2. **Análisis Técnico** - Explicación detallada
3. **Ejemplos** - Código o comandos cuando aplique
4. **Referencias** - CVEs, papers, recursos adicionales
"""


class VulnResearcherAgent:
    """Agent specialized in vulnerability research."""

    def __init__(self, client: MinkaClient) -> None:
        """Initialize the vulnerability researcher agent.

        Args:
            client: Minka Copilot client instance
        """
        self.client = client
        self.session = None
        self.tools = self._register_tools()

    def _register_tools(self) -> Dict[str, Any]:
        """Register available tools for this agent."""
        return {
            "search_cve": self._search_cve,
            "get_exploit_db": self._get_exploit_db,
            "analyze_code": self._analyze_code,
            "generate_poc_template": self._generate_poc_template,
        }

    async def create_session(self) -> None:
        """Create a new agent session."""
        # Define tools schema
        tools = [
            {
                "name": "search_cve",
                "description": "Search for CVE information",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "description": "CVE ID (e.g., CVE-2021-44228)"}
                    },
                    "required": ["cve_id"],
                },
            },
            {
                "name": "get_exploit_db",
                "description": "Search Exploit-DB for exploits",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string", "description": "Search query"}},
                    "required": ["query"],
                },
            },
            {
                "name": "generate_poc_template",
                "description": "Generate PoC template for educational purposes",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vuln_type": {
                            "type": "string",
                            "description": "Type of vulnerability (sqli, xss, buffer_overflow, etc.)",
                        },
                        "language": {
                            "type": "string",
                            "description": "Programming language (python, c, java, etc.)",
                        },
                    },
                    "required": ["vuln_type"],
                },
            },
        ]

        self.session = await self.client.create_session(
            system_prompt=VULN_RESEARCHER_PROMPT,
            tools=tools,
            streaming=True,
        )

    async def process(self, message: str) -> str:
        """Process user message.

        Args:
            message: User input message

        Returns:
            Agent response
        """
        if not self.session:
            raise RuntimeError("Session not created. Call create_session() first.")

        try:
            response = await self.client.send_message(message, stream=False)
            return response
        except Exception as e:
            logger.error("Error processing message", error=str(e))
            return f"Error: {str(e)}"

    async def _search_cve(self, cve_id: str) -> Dict[str, Any]:
        """Search CVE information from NVD API.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            CVE information
        """
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                if data.get("vulnerabilities"):
                    cve = data["vulnerabilities"][0]["cve"]
                    return {
                        "id": cve.get("id"),
                        "description": cve.get("descriptions", [{}])[0].get("value"),
                        "severity": cve.get("metrics", {})
                        .get("cvssMetricV31", [{}])[0]
                        .get("cvssData", {})
                        .get("baseSeverity", "Unknown"),
                        "published": cve.get("published"),
                        "modified": cve.get("lastModified"),
                    }
                return {"error": "CVE not found"}

        except Exception as e:
            logger.error("Error searching CVE", error=str(e))
            return {"error": str(e)}

    async def _get_exploit_db(self, query: str) -> Dict[str, Any]:
        """Search Exploit-DB.

        Args:
            query: Search query

        Returns:
            List of exploits
        """
        try:
            url = f"https://www.exploit-db.com/search?description={query}&type=remote"
            # Note: Exploit-DB doesn't have a public API, this is a placeholder
            return {
                "message": f"Search Exploit-DB manually: https://www.exploit-db.com/search?description={query}",
                "results": [],
            }
        except Exception as e:
            return {"error": str(e)}

    async def _analyze_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Analyze code for vulnerabilities.

        Args:
            code: Source code to analyze
            language: Programming language

        Returns:
            Analysis results
        """
        # This is a simplified version - real implementation would use AST parsing
        findings = []

        # Simple pattern matching for common vulnerabilities
        dangerous_patterns = {
            "python": [
                ("eval(", "Uso potencialmente peligroso de eval()"),
                ("exec(", "Uso potencialmente peligroso de exec()"),
                ("input(", "Posible vulnerabilidad de inyección"),
                ("subprocess", "Verificar uso seguro de subprocess"),
                ("pickle.loads", "Deserialización insegura"),
            ],
            "javascript": [
                ("eval(", "Uso peligroso de eval()"),
                ("innerHTML", "Posible XSS"),
                ("document.write", "Posible XSS"),
            ],
        }

        patterns = dangerous_patterns.get(language, [])
        for pattern, description in patterns:
            if pattern in code:
                findings.append({"pattern": pattern, "description": description})

        return {
            "language": language,
            "findings": findings,
            "risk_level": "high" if len(findings) > 2 else "medium" if findings else "low",
        }

    async def _generate_poc_template(
        self, vuln_type: str, language: str = "python"
    ) -> Dict[str, Any]:
        """Generate PoC template.

        Args:
            vuln_type: Type of vulnerability
            language: Programming language

        Returns:
            PoC template
        """
        templates = {
            "sqli": {
                "python": '''#!/usr/bin/env python3
"""
PoC educativo: SQL Injection
Este script demuestra cómo funciona una inyección SQL
para fines educativos. NO usar en sistemas sin autorización.
"""

import requests

def test_sqli_vulnerable(url, parameter):
    """
    Prueba básica de SQL injection.
    
    Args:
        url: URL objetivo
        parameter: Parámetro vulnerable
    """
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT null,null --",
    ]
    
    for payload in payloads:
        test_url = f"{url}?{parameter}={payload}"
        print(f"Testing: {test_url}")
        # response = requests.get(test_url)
        # Analizar respuesta

if __name__ == "__main__":
    # Ejemplo de uso (comentado para evitar uso accidental)
    # test_sqli_vulnerable("http://localhost/vulnerable.php", "id")
    print("PoC Template - SQL Injection")
''',
                "description": "Template para demostrar SQL Injection",
            },
            "xss": {
                "python": '''#!/usr/bin/env python3
"""
PoC educativo: Cross-Site Scripting (XSS)
Demostración de cómo funciona XSS.
"""

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
]

def generate_xss_test_page():
    """Genera una página de prueba XSS."""
    html = """
    <!DOCTYPE html>
    <html>
    <head><title>XSS Test</title></head>
    <body>
        <h1>XSS Testing Page</h1>
        <form method="POST">
            <input type="text" name="input" placeholder="Enter text">
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    """
    return html
''',
                "description": "Template para demostrar XSS",
            },
            "buffer_overflow": {
                "c": """/*
 * PoC educativo: Buffer Overflow
 * Compilar: gcc -fno-stack-protector -o bof_demo bof_demo.c
 * 
 * ADVERTENCIA: Solo para fines educativos en entornos controlados
 */

#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    // VULNERABLE: No hay verificación de límites
    strcpy(buffer, input);
    printf("Input: %s\\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s <input>\\n", argv[0]);
        return 1;
    }
    
    vulnerable_function(argv[1]);
    return 0;
}
""",
                "description": "Template para demostrar Buffer Overflow",
            },
        }

        vuln_templates = templates.get(vuln_type, {})
        template = vuln_templates.get(language, "# Template no disponible")

        return {
            "vulnerability": vuln_type,
            "language": language,
            "template": template,
            "description": vuln_templates.get("description", ""),
            "warning": "Este código es SOLO para fines educativos y testing autorizado",
        }
