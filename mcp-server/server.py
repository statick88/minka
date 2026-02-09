#!/usr/bin/env python3
"""
Minka MCP Server - Main Server Module

GitHub Copilot SDK Integration for Minka Personality

Usage:
    python server.py

This server exposes Minka's tools via Model Context Protocol (MCP)
for integration with GitHub Copilot.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.types import Tool, TextContent

from .tools.experts import search_experts, get_citation
from .tools.ai_security import search_ai_security, get_ai_paper
from .tools.cases import get_case_study
from .tools.quotes import get_quote
from .tools.narrative import generate_narrative
from .tools.vulnerabilities import get_cve_info
from .tools.ucm_curriculum import get_ucm_module
from .tools.clean_architecture import get_clean_arch_info

app = Server("minka-mcp-server")


@app.list_tools()
async def list_tools() -> List[Tool]:
    """Define las herramientas disponibles para Copilot."""
    return [
        Tool(
            name="minka-experts",
            description="Search and cite security researchers and institutions",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (researcher name, topic, institution)",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["brief", "detailed", "citation"],
                        "default": "brief",
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="minka-ai-security",
            description="Search AI security resources: malware detection, SOC automation, offensive AI, AI defense",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Topic: malware_detection, soc_automation, offensive_ai, ai_defense, adversarial_ml",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["brief", "detailed", "citation", "tools"],
                        "default": "brief",
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="minka-ai-research",
            description="Search AI security papers and research (NIST, arXiv, IEEE)",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Topic: adversarial_ml, evasion, poisoning, inference, adversarial_defenses",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["brief", "detailed", "citation"],
                        "default": "brief",
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="minka-cases",
            description="Get case studies for security concepts",
            inputSchema={
                "type": "object",
                "properties": {
                    "topic": {"type": "string", "description": "Security topic or technique"},
                    "style": {
                        "type": "string",
                        "enum": ["mitnick", "modern", "academic"],
                        "default": "mitnick",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["summary", "full", "narrative"],
                        "default": "summary",
                    },
                },
                "required": ["topic"],
            },
        ),
        Tool(
            name="minka-quote",
            description="Get Mitnick-style quote for context",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": [
                            "curiosity",
                            "perspective",
                            "social_engineering",
                            "education",
                            "security",
                        ],
                    },
                    "tone": {
                        "type": "string",
                        "enum": ["inspirational", "technical", "humorous"],
                        "default": "inspirational",
                    },
                },
            },
        ),
        Tool(
            name="minka-narrative",
            description="Generate narrative explanation for security concept",
            inputSchema={
                "type": "object",
                "properties": {
                    "concept": {"type": "string", "description": "Security concept to explain"},
                    "audience": {
                        "type": "string",
                        "enum": ["beginner", "intermediate", "advanced"],
                        "default": "intermediate",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["story", "technical", "mixed"],
                        "default": "mixed",
                    },
                },
                "required": ["concept"],
            },
        ),
        Tool(
            name="minka-vuln",
            description="Search CVEs and vulnerability research",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve": {"type": "string", "description": "CVE ID (e.g., CVE-2021-44228)"},
                    "format": {
                        "type": "string",
                        "enum": ["brief", "detailed", "exploit", "mitigation"],
                        "default": "brief",
                    },
                },
                "required": ["cve"],
            },
        ),
        Tool(
            name="minka-ucm",
            description="Get UCM Master curriculum information",
            inputSchema={
                "type": "object",
                "properties": {
                    "module": {
                        "type": "string",
                        "enum": [
                            "red_team",
                            "blue_team",
                            "purple_team",
                            "dfir",
                            "grc",
                            "ia_security",
                            "cryptography",
                            "web_security",
                            "iot_security",
                        ],
                    },
                    "format": {
                        "type": "string",
                        "enum": ["summary", "detailed", "tools", "frameworks"],
                        "default": "summary",
                    },
                },
                "required": ["module"],
            },
        ),
        Tool(
            name="minka-cleanarch",
            description="Get Clean Architecture principles and examples",
            inputSchema={
                "type": "object",
                "properties": {
                    "principle": {
                        "type": "string",
                        "enum": [
                            "solid",
                            "dependency_rule",
                            "clean_code",
                            "clean_architecture",
                            "clean_agile",
                            "boy_scout_rule",
                        ],
                    },
                    "language": {
                        "type": "string",
                        "enum": ["python", "javascript", "typescript", "java", "csharp", "general"],
                        "default": "general",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["explanation", "example", "both"],
                        "default": "explanation",
                    },
                },
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Ejecuta las herramientas."""
    try:
        if name == "minka-experts":
            result = await search_experts(
                arguments.get("query", ""), arguments.get("format", "brief")
            )
        elif name == "minka-ai-security":
            result = await search_ai_security(
                arguments.get("query", ""), arguments.get("format", "brief")
            )
        elif name == "minka-ai-research":
            result = await get_ai_paper(
                arguments.get("query", ""), arguments.get("format", "brief")
            )
        elif name == "minka-cases":
            result = await get_case_study(
                arguments.get("topic", ""),
                arguments.get("style", "mitnick"),
                arguments.get("format", "summary"),
            )
        elif name == "minka-quote":
            result = await get_quote(
                arguments.get("category", "curiosity"), arguments.get("tone", "inspirational")
            )
        elif name == "minka-narrative":
            result = await generate_narrative(
                arguments.get("concept", ""),
                arguments.get("audience", "intermediate"),
                arguments.get("format", "mixed"),
            )
        elif name == "minka-vuln":
            result = await get_cve_info(arguments.get("cve", ""), arguments.get("format", "brief"))
        elif name == "minka-ucm":
            result = await get_ucm_module(
                arguments.get("module", ""), arguments.get("format", "summary")
            )
        elif name == "minka-cleanarch":
            result = await get_clean_arch_info(
                arguments.get("principle", "solid"),
                arguments.get("language", "general"),
                arguments.get("format", "explanation"),
            )
        else:
            result = f"Unknown tool: {name}. Available tools: minka-experts, minka-ai-security, minka-ai-research, minka-cases, minka-quote, minka-narrative, minka-vuln, minka-ucm, minka-cleanarch"

        return [TextContent(type="text", text=result)]

    except Exception as e:
        error_msg = f"Error executing {name}: {str(e)}"
        return [TextContent(type="text", text=error_msg)]


async def main():
    """Main entry point for the MCP server."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
