"""Security tools integration for Minka MCP."""

import subprocess
import asyncio
from typing import Any, Dict, List, Optional
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


class SecurityTools:
    """Collection of security scanning tools."""

    @staticmethod
    async def run_nmap(target: str, ports: str = "-p-", args: str = "-sV") -> Dict[str, Any]:
        """Execute nmap scan.

        Args:
            target: Target IP or hostname
            ports: Port specification
            args: Additional arguments

        Returns:
            Scan results
        """
        cmd = f"nmap {args} {ports} {target}"

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300,
            )

            if proc.returncode == 0:
                return {
                    "success": True,
                    "tool": "nmap",
                    "target": target,
                    "output": stdout.decode(),
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode(),
                }

        except asyncio.TimeoutError:
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    async def check_headers(url: str) -> Dict[str, Any]:
        """Check security headers of a URL.

        Args:
            url: Target URL

        Returns:
            Headers analysis
        """
        import httpx

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0)
                headers = response.headers

                security_headers = {
                    "Strict-Transport-Security": headers.get(
                        "strict-transport-security", "Missing"
                    ),
                    "Content-Security-Policy": headers.get("content-security-policy", "Missing"),
                    "X-Frame-Options": headers.get("x-frame-options", "Missing"),
                    "X-Content-Type-Options": headers.get("x-content-type-options", "Missing"),
                    "X-XSS-Protection": headers.get("x-xss-protection", "Missing"),
                    "Referrer-Policy": headers.get("referrer-policy", "Missing"),
                }

                return {
                    "success": True,
                    "tool": "header_check",
                    "url": url,
                    "headers": security_headers,
                    "missing_headers": [k for k, v in security_headers.items() if v == "Missing"],
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    async def search_cve(cve_id: str) -> Dict[str, Any]:
        """Search CVE in NVD database.

        Args:
            cve_id: CVE identifier

        Returns:
            CVE information
        """
        import httpx

        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0)
                data = response.json()

                if data.get("vulnerabilities"):
                    cve = data["vulnerabilities"][0]["cve"]
                    return {
                        "success": True,
                        "cve_id": cve.get("id"),
                        "description": cve.get("descriptions", [{}])[0].get("value"),
                        "published": cve.get("published"),
                        "modified": cve.get("lastModified"),
                    }
                else:
                    return {"success": False, "error": "CVE not found"}

        except Exception as e:
            return {"success": False, "error": str(e)}
