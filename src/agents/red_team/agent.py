"""Red Team Agent - Offensive security operations.

This agent specializes in:
- Exploit research and analysis
- Vulnerability exploitation techniques
- Payload generation and encoding
- Lateral movement strategies
- Post-exploitation guidance

Following Clean Architecture and Uncle Bob's principles.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table

logger = structlog.get_logger(__name__)
console = Console()


class ExploitType(Enum):
    """Types of exploits."""

    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    CSRF = "csrf"
    RCE = "remote_code_execution"
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    SSRF = "server_side_request_forgery"
    AUTH_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    BUFFER_OVERFLOW = "buffer_overflow"
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"


class Severity(Enum):
    """Exploit severity levels."""

    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class Exploit:
    """Represents a security exploit."""

    cve_id: Optional[str]
    exploit_type: ExploitType
    severity: Severity
    title: str
    description: str
    affected_systems: List[str]
    remediation: str
    references: List[str]
    created_at: datetime = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "exploit_type": self.exploit_type.value,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "affected_systems": self.affected_systems,
            "remediation": self.remediation,
            "references": self.references,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ExploitationResult:
    """Result of an exploitation attempt."""

    success: bool
    exploit: Exploit
    findings: Dict[str, Any]
    evidence: List[str]
    recommendations: List[str]
    error_message: Optional[str] = None


class RedTeamAgent:
    """Red Team Agent for offensive security operations.

    This agent provides guidance and analysis for:
    - Identifying exploitable vulnerabilities
    - Understanding exploitation techniques
    - Generating safe test payloads
    - Documenting findings for remediation
    """

    def __init__(self, copilot_client: Optional[Any] = None) -> None:
        """Initialize the Red Team Agent.

        Args:
            copilot_client: Optional Copilot client for AI assistance
        """
        self.copilot_client = copilot_client
        self.exploit_db: Dict[str, Exploit] = {}
        self.session_logs: List[Dict[str, Any]] = []

    async def initialize(self) -> None:
        """Initialize the agent and load exploit database."""
        logger.info("Initializing Red Team Agent")
        await self._load_exploit_database()
        logger.info("Red Team Agent initialized", exploit_count=len(self.exploit_db))

    async def _load_exploit_database(self) -> None:
        """Load exploit database from local storage."""
        exploit_file = Path("data/exploits/exploit_db.json")
        if exploit_file.exists():
            try:
                data = json.loads(exploit_file.read_text())
                for item in data:
                    exploit = Exploit(
                        cve_id=item.get("cve_id"),
                        exploit_type=ExploitType(item["exploit_type"]),
                        severity=Severity(item["severity"]),
                        title=item["title"],
                        description=item["description"],
                        affected_systems=item["affected_systems"],
                        remediation=item["remediation"],
                        references=item["references"],
                        created_at=datetime.fromisoformat(item["created_at"]),
                    )
                    self.exploit_db[item["cve_id"] or item["title"]] = exploit
                logger.info("Loaded exploit database", count=len(self.exploit_db))
            except Exception as e:
                logger.warning("Failed to load exploit database", error=str(e))
                await self._create_default_exploits()

    async def _create_default_exploits(self) -> None:
        """Create default exploit entries for common vulnerabilities."""
        default_exploits = [
            Exploit(
                cve_id="CVE-2021-44228",
                exploit_type=ExploitType.LOG4J,
                severity=Severity.CRITICAL,
                title="Apache Log4j2 JNDI Features Used in Message Lookup",
                description="Apache Log4j2 <=2.14.1 does not protect against "
                "malicious user input in message lookup patterns.",
                affected_systems=["Apache Log4j2 2.0-beta9 through 2.14.1"],
                remediation="Upgrade to Log4j 2.15.0 or later",
                references=[
                    "https://logging.apache.org/log4j/2.x/security.html",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
                ],
            ),
            Exploit(
                cve_id="CVE-2017-0144",
                exploit_type=ExploitType.RCE,
                severity=Severity.CRITICAL,
                title="SMBv1 Vulnerability (WannaCry)",
                description="The SMBv1 protocol in Microsoft Windows Vista, "
                "Windows Server 2008, and Windows 7 is vulnerable to remote code execution.",
                affected_systems=[
                    "Windows Vista",
                    "Windows Server 2008",
                    "Windows 7",
                ],
                remediation="Disable SMBv1 and apply security updates",
                references=[
                    "https://technet.microsoft.com/en-us/library/security/ms17-010.aspx",
                ],
            ),
            Exploit(
                cve_id=None,
                exploit_type=ExploitType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="Generic SQL Injection Pattern",
                description="SQL injection vulnerabilities occur when untrusted data "
                "is concatenated into database queries without proper sanitization.",
                affected_systems=["Any database-backed application"],
                remediation="Use parameterized queries, ORM, or prepared statements",
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                ],
            ),
        ]

        for exploit in default_exploits:
            key = exploit.cve_id or exploit.title
            self.exploit_db[key] = exploit

        logger.info("Created default exploits", count=len(self.exploit_db))

    async def research_exploit(
        self,
        vulnerability_description: str,
        target_systems: Optional[List[str]] = None,
    ) -> List[Exploit]:
        """Research exploits for a given vulnerability.

        Args:
            vulnerability_description: Description of the vulnerability
            target_systems: Optional list of target systems

        Returns:
            List of matching exploits
        """
        logger.info("Researching exploits", description=vulnerability_description)

        if self.copilot_client:
            await self._research_with_copilot(vulnerability_description, target_systems)

        matches = self._find_matching_exploits(vulnerability_description, target_systems)
        logger.info("Found exploits", count=len(matches))

        self.session_logs.append(
            {
                "timestamp": datetime.now().isoformat(),
                "action": "research_exploit",
                "query": vulnerability_description,
                "results_count": len(matches),
            }
        )

        return matches

    async def _research_with_copilot(
        self,
        vulnerability_description: str,
        target_systems: Optional[List[str]] = None,
    ) -> None:
        """Use Copilot to research exploits."""
        if not self.copilot_client:
            return

        prompt = f"""
        Research exploits for the following vulnerability:
        {vulnerability_description}
        Target systems: {", ".join(target_systems) if target_systems else "General"}
        
        Provide:
        1. CVSS score if available
        2. Public exploit availability
        3. Real-world exploitation status
        4. Remediation steps
        """

        try:
            response = await self.copilot_client.send_message(prompt)
            logger.info("Copilot research completed", response_length=len(response))
        except Exception as e:
            logger.warning("Copilot research failed", error=str(e))

    def _find_matching_exploits(
        self,
        vulnerability_description: str,
        target_systems: Optional[List[str]] = None,
    ) -> List[Exploit]:
        """Find exploits matching the vulnerability description."""
        matches = []
        description_lower = vulnerability_description.lower()

        keywords = {
            ExploitType.SQL_INJECTION: ["sql", "injection", "database", "query"],
            ExploitType.XSS: ["xss", "cross-site", "scripting", "javascript"],
            ExploitType.RCE: ["rce", "remote code", "command injection", "arbitrary code"],
            ExploitType.LFI: ["lfi", "file inclusion", "file read"],
            ExploitType.SSRF: ["ssrf", "server-side request", "internal services"],
            ExploitType.AUTH_BYPASS: ["authentication bypass", "auth bypass", "login bypass"],
        }

        for key, exploit in self.exploit_db.items():
            score = 0

            description_words = exploit.description.lower().split()
            for word in description_words:
                if word in description_lower:
                    score += 1

            if exploit.cve_id and exploit.cve_id.lower() in description_lower:
                score += 5

            if target_systems:
                for system in target_systems:
                    if any(s.lower() in system.lower() for s in exploit.affected_systems):
                        score += 2

            if score >= 2:
                matches.append((exploit, score))

        matches.sort(key=lambda x: x[1], reverse=True)
        return [m[0] for m in matches]

    def generate_payload(
        self,
        exploit_type: ExploitType,
        target: str,
        encode: bool = True,
    ) -> Dict[str, Any]:
        """Generate a safe test payload for the given exploit type.

        Args:
            exploit_type: Type of exploit
            target: Target system/application
            encode: Whether to URL-encode the payload

        Returns:
            Dictionary with payload information
        """
        logger.info("Generating payload", exploit_type=exploit_type.value, target=target)

        payload_templates = {
            ExploitType.SQL_INJECTION: [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "admin'--",
                "UNION SELECT 1,2,3--",
            ],
            ExploitType.XSS: [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
            ],
            ExploitType.COMMAND_INJECTION: [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "$(id)",
            ],
            ExploitType.LFI: [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "/etc/hosts",
            ],
            ExploitType.PATH_TRAVERSAL: [
                "../../../etc/passwd",
                "....//....//etc/passwd",
                "/../../etc/passwd",
            ],
        }

        base_payloads = payload_templates.get(exploit_type, ["TEST_PAYLOAD"])

        result = {
            "exploit_type": exploit_type.value,
            "target": target,
            "payloads": base_payloads,
            "encoded": [],
            "warnings": [
                "Only use in authorized testing environments",
                "Ensure proper scope definition before testing",
                "Document all findings for remediation",
            ],
            "recommendations": [],
        }

        if encode:
            import urllib.parse

            for payload in base_payloads:
                encoded = urllib.parse.quote(payload, safe="")
                result["encoded"].append(encoded)

        self.session_logs.append(
            {
                "timestamp": datetime.now().isoformat(),
                "action": "generate_payload",
                "exploit_type": exploit_type.value,
                "target": target,
                "payload_count": len(base_payloads),
            }
        )

        return result

    def display_exploits(self, exploits: List[Exploit]) -> None:
        """Display exploits in a rich table format."""
        if not exploits:
            console.print("[yellow]No matching exploits found[/yellow]")
            return

        table = Table(title="Matching Exploits")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Severity", style="red")
        table.add_column("Title", style="green")

        severity_colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange_red1",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "green",
            Severity.INFO: "blue",
        }

        for exploit in exploits:
            severity_color = severity_colors.get(exploit.severity, "white")
            table.add_row(
                exploit.cve_id or "N/A",
                exploit.exploit_type.value,
                f"[{severity_color}]{exploit.severity.name}[/{severity_color}]",
                exploit.title,
            )

        console.print(table)

        for exploit in exploits:
            console.print(
                Panel(
                    JSON(json.dumps(exploit.to_dict(), indent=2)),
                    title=f"Details: {exploit.title}",
                    expand=False,
                )
            )

    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of the current session."""
        return {
            "total_exploits": len(self.exploit_db),
            "session_logs": self.session_logs,
            "actions_taken": len(self.session_logs),
        }


async def create_red_team_agent(copilot_client: Optional[Any] = None) -> RedTeamAgent:
    """Factory function to create a Red Team Agent.

    Args:
        copilot_client: Optional Copilot client

    Returns:
        Initialized RedTeamAgent instance
    """
    agent = RedTeamAgent(copilot_client)
    await agent.initialize()
    return agent
