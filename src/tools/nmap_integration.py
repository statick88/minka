"""MCP Tools for security scanning and analysis."""

import asyncio
import json
import subprocess
from typing import Any, Dict, List, Optional
from pathlib import Path

import structlog
from core.config import get_settings

logger = structlog.get_logger(__name__)


class NmapTool:
    """Nmap integration for network scanning."""

    def __init__(self) -> None:
        self.timeout = get_settings().max_tool_execution_time

    async def scan(
        self,
        target: str,
        ports: Optional[str] = None,
        arguments: str = "-sV -sC",
    ) -> Dict[str, Any]:
        """Run nmap scan against target.
        
        Args:
            target: IP or hostname to scan
            ports: Specific ports (e.g., "80,443" or "1-1000")
            arguments: Additional nmap arguments
            
        Returns:
            Scan results
        """
        cmd = ["nmap", "-oX", "-"]
        
        if ports:
            cmd.extend(["-p", ports])
        
        cmd.extend(arguments.split())
        cmd.append(target)

        try:
            logger.info("Running nmap scan", target=target, ports=ports)
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout,
            )
            
            if proc.returncode != 0:
                logger.error("Nmap scan failed", error=stderr.decode())
                return {"error": stderr.decode(), "success": False}
            
            # Parse XML output (simplified)
            output = stdout.decode()
            return {
                "success": True,
                "target": target,
                "raw_output": output[:5000],  # Limit output size
                "scan_type": "nmap",
            }
            
        except asyncio.TimeoutError:
            logger.error("Nmap scan timed out")
            return {"error": "Scan timed out", "success": False}
        except Exception as e:
            logger.error("Nmap scan error", error=str(e))
            return {"error": str(e), "success": False}

    async def quick_scan(self, target: str) -> Dict[str, Any]:
        """Quick scan of top 1000 ports.
        
        Args:
            target: Target to scan
            
        Returns:
            Scan results
        """
        return await self.scan(target, arguments="--top-ports 1000 -sV")


class CodeAnalyzerTool:
    """Static code analysis for security issues."""

    DANGEROUS_PATTERNS = {
        "python": [
            (r"eval\s*\(", "Uso peligroso de eval()"),
            (r"exec\s*\(", "Uso peligroso de exec()"),
            (r"subprocess\.call.*shell\s*=\s*True", "Shell=True puede ser peligroso"),
            (r"pickle\.loads?\s*\(", "Deserialización insegura con pickle"),
            (r"yaml\.load\s*\([^)]*\)", "yaml.load() sin Loader es inseguro"),
            (r"input\s*\(", "Uso de input() - verificar sanitización"),
            (r"os\.system\s*\(", "Command injection potencial"),
            (r"\.format\s*\([^)]*\)", "Posible format string vulnerability"),
            (r"f['\"].*\{.*\}.*['\"]\.format", "Posible f-string vulnerability"),
        ],
        "javascript": [
            (r"eval\s*\(", "Uso peligroso de eval()"),
            (r"innerHTML\s*[=+]", "Posible XSS via innerHTML"),
            (r"document\.write\s*\(", "Posible XSS via document.write"),
            (r"setTimeout\s*\(\s*['\"\"]