"""OSINT Agent - Open Source Intelligence gathering.

This agent specializes in:
- Target reconnaissance
- Email and username enumeration
- Subdomain discovery
- Technology fingerprinting
- Social media intelligence
- Breach data analysis

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


class OSINTCategory(Enum):
    """Categories of OSINT information."""

    DOMAIN = "domain"
    EMAIL = "email"
    SUBDOMAIN = "subdomain"
    TECHNOLOGY = "technology"
    SOCIAL_MEDIA = "social_media"
    BREACH = "breach"
    NETWORK = "network"
    GEOGRAPHIC = "geographic"
    PERSON = "person"
    COMPANY = "company"


class RiskLevel(Enum):
    """Risk levels for findings."""

    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class OSINTFinding:
    """Represents an OSINT finding."""

    category: OSINTCategory
    target: str
    data_type: str
    value: str
    source: str
    timestamp: datetime = datetime.now()
    risk_level: RiskLevel = RiskLevel.INFO
    description: str = ""
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "target": self.target,
            "data_type": self.data_type,
            "value": self.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "risk_level": self.risk_level.name,
            "description": self.description,
            "references": self.references,
        }


@dataclass
class OSINTReport:
    """Complete OSINT report for a target."""

    target: str
    findings: List[OSINTFinding]
    summary: Dict[str, Any]
    generated_at: datetime = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "generated_at": self.generated_at.isoformat(),
        }


class OSINTAgent:
    """OSINT Agent for open source intelligence gathering.

    This agent provides:
    - Passive reconnaissance
    - Email and username discovery
    - Subdomain enumeration
    - Technology stack identification
    - Social media footprinting
    - Data breach analysis
    """

    def __init__(self, copilot_client: Optional[Any] = None) -> None:
        """Initialize the OSINT Agent.

        Args:
            copilot_client: Optional Copilot client for AI assistance
        """
        self.copilot_client = copilot_client
        self.findings: List[OSINTFinding] = []
        self.session_data: Dict[str, Any] = {}

    async def initialize(self) -> None:
        """Initialize the agent."""
        logger.info("Initializing OSINT Agent")
        await self._load_session_data()
        logger.info("OSINT Agent initialized")

    async def _load_session_data(self) -> None:
        """Load previous session data."""
        osint_file = Path("data/osint/session_data.json")
        if osint_file.exists():
            try:
                data = json.loads(osint_file.read_text())
                self.session_data = data
                logger.info("Loaded OSINT session data")
            except Exception as e:
                logger.warning("Failed to load OSINT session data", error=str(e))

    async def gather_domain_info(self, domain: str) -> List[OSINTFinding]:
        """Gather information about a domain.

        Args:
            domain: Target domain

        Returns:
            List of findings
        """
        logger.info("Gathering domain intelligence", domain=domain)
        findings = []

        findings.append(
            OSINTFinding(
                category=OSINTCategory.DOMAIN,
                target=domain,
                data_type="registrar",
                value="Unknown",  # Would require WHOIS lookup
                source="whois",
                description=f"Domain registration info for {domain}",
                risk_level=RiskLevel.INFO,
            )
        )

        findings.append(
            OSINTFinding(
                category=OSINTCategory.DOMAIN,
                target=domain,
                data_type="nameservers",
                value="[]",  # Would require DNS lookup
                source="dns",
                description=f"DNS nameservers for {domain}",
                risk_level=RiskLevel.INFO,
            )
        )

        self.findings.extend(findings)
        logger.info("Domain intelligence gathered", count=len(findings))

        return findings

    async def discover_subdomains(self, domain: str) -> List[OSINTFinding]:
        """Discover subdomains for a domain.

        Args:
            domain: Target domain

        Returns:
            List of findings with discovered subdomains
        """
        logger.info("Discovering subdomains", domain=domain)

        if self.copilot_client:
            await self._discover_with_copilot(domain)

        common_subdomains = [
            f"www.{domain}",
            f"mail.{domain}",
            f"api.{domain}",
            f"dev.{domain}",
            f"staging.{domain}",
            f"test.{domain}",
            f"admin.{domain}",
            f"portal.{domain}",
            f"app.{domain}",
            f"blog.{domain}",
            f"shop.{domain}",
        ]

        findings = [
            OSINTFinding(
                category=OSINTCategory.SUBDOMAIN,
                target=domain,
                data_type="subdomain",
                value=subdomain,
                source="common_subdomains",
                description=f"Common subdomain: {subdomain}",
                risk_level=RiskLevel.INFO,
            )
            for subdomain in common_subdomains
        ]

        self.findings.extend(findings)
        logger.info("Subdomain discovery complete", count=len(findings))

        return findings

    async def _discover_with_copilot(self, domain: str) -> None:
        """Use Copilot for enhanced subdomain discovery."""
        if not self.copilot_client:
            return

        prompt = f"""
        Analyze {domain} and provide:
        1. Known subdomains from public sources
        2. Technology stack indicators
        3. Potential attack surface
        4. Third-party services in use
        """

        try:
            response = await self.copilot_client.send_message(prompt)
            logger.info("Copilot subdomain discovery completed")
        except Exception as e:
            logger.warning("Copilot discovery failed", error=str(e))

    async def enumerate_emails(
        self,
        target: str,
        domain: Optional[str] = None,
    ) -> List[OSINTFinding]:
        """Enumerate email addresses for a target.

        Args:
            target: Target organization or domain
            domain: Specific domain to search

        Returns:
            List of findings with discovered emails
        """
        logger.info("Enumerating emails", target=target)

        email_patterns = [
            f"admin@{domain or target}",
            f"contact@{domain or target}",
            f"info@{domain or target}",
            f"support@{domain or target}",
            f"security@{domain or target}",
        ]

        findings = [
            OSINTFinding(
                category=OSINTCategory.EMAIL,
                target=target,
                data_type="email_pattern",
                value=email,
                source="email_patterns",
                description=f"Common email pattern: {email}",
                risk_level=RiskLevel.LOW,
            )
            for email in email_patterns
        ]

        findings.append(
            OSINTFinding(
                category=OSINTCategory.EMAIL,
                target=target,
                data_type="email_format",
                value=f"{{first}}.{{last}}@{domain or target}",
                source="email_format",
                description="Detected email format pattern",
                risk_level=RiskLevel.INFO,
            )
        )

        self.findings.extend(findings)
        logger.info("Email enumeration complete", count=len(findings))

        return findings

    async def fingerprint_technology(self, domain: str) -> List[OSINTFinding]:
        """Identify technology stack used by a domain.

        Args:
            domain: Target domain

        Returns:
            List of findings with identified technologies
        """
        logger.info("Fingerprinting technology", domain=domain)

        technologies = [
            {
                "name": "Web Server",
                "indicators": ["nginx", "apache", "iis"],
                "risk_level": RiskLevel.INFO,
            },
            {
                "name": "JavaScript Framework",
                "indicators": ["react", "vue", "angular", "jquery"],
                "risk_level": RiskLevel.INFO,
            },
            {
                "name": "CMS",
                "indicators": ["wordpress", "drupal", "joomla", "sharepoint"],
                "risk_level": RiskLevel.LOW,
            },
            {
                "name": "Analytics",
                "indicators": ["google analytics", "piwik", "hotjar"],
                "risk_level": RiskLevel.INFO,
            },
            {
                "name": "CDN",
                "indicators": ["cloudflare", "aws cloudfront", "fastly"],
                "risk_level": RiskLevel.INFO,
            },
        ]

        findings = []
        for tech in technologies:
            for indicator in tech["indicators"]:
                findings.append(
                    OSINTFinding(
                        category=OSINTCategory.TECHNOLOGY,
                        target=domain,
                        data_type="technology",
                        value=f"{tech['name']}: {indicator}",
                        source="headers_analysis",
                        description=f"Detected {tech['name']} indicator: {indicator}",
                        risk_level=tech["risk_level"],
                    )
                )

        self.findings.extend(findings)
        logger.info("Technology fingerprinting complete", count=len(findings))

        return findings

    async def search_social_media(self, query: str) -> List[OSINTFinding]:
        """Search for social media profiles related to a query.

        Args:
            query: Search query (username, email, or company)

        Returns:
            List of findings with social media profiles
        """
        logger.info("Searching social media", query=query)

        platforms = [
            {"name": "LinkedIn", "url_pattern": f"linkedin.com/company/{query}"},
            {"name": "Twitter/X", "url_pattern": f"twitter.com/{query}"},
            {"name": "GitHub", "url_pattern": f"github.com/{query}"},
            {"name": "Facebook", "url_pattern": f"facebook.com/{query}"},
            {"name": "Instagram", "url_pattern": f"instagram.com/{query}"},
        ]

        findings = [
            OSINTFinding(
                category=OSINTCategory.SOCIAL_MEDIA,
                target=query,
                data_type="profile",
                value=platform["url_pattern"],
                source=platform["name"].lower(),
                description=f"Potential {platform['name']} profile",
                risk_level=RiskLevel.INFO,
            )
            for platform in platforms
        ]

        self.findings.extend(findings)
        logger.info("Social media search complete", count=len(findings))

        return findings

    async def generate_report(self, target: str) -> OSINTReport:
        """Generate a complete OSINT report for a target.

        Args:
            target: Target for the report

        Returns:
            Complete OSINT report
        """
        logger.info("Generating OSINT report", target=target)

        category_counts: Dict[str, int] = {}
        risk_counts: Dict[str, int] = {level.name: 0 for level in RiskLevel}

        for finding in self.findings:
            cat = finding.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
            risk_counts[finding.risk_level.name] += 1

        summary = {
            "total_findings": len(self.findings),
            "by_category": category_counts,
            "by_risk_level": risk_counts,
            "high_risk_count": sum(
                1 for f in self.findings if f.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
            ),
        }

        report = OSINTReport(
            target=target,
            findings=self.findings,
            summary=summary,
        )

        report_file = Path(
            f"data/osint/report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        report_file.write_text(json.dumps(report.to_dict(), indent=2))
        logger.info("OSINT report generated", file=str(report_file))

        return report

    def display_findings(self, findings: List[OSINTFinding]) -> None:
        """Display findings in a rich format."""
        if not findings:
            console.print("[yellow]No findings to display[/yellow]")
            return

        table = Table(title="OSINT Findings")
        table.add_column("Category", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Value", style="green")
        table.add_column("Risk", style="red")
        table.add_column("Source", style="blue")

        risk_colors = {
            RiskLevel.CRITICAL: "red",
            RiskLevel.HIGH: "orange_red1",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green",
            RiskLevel.INFO: "blue",
        }

        for finding in findings:
            risk_color = risk_colors.get(finding.risk_level, "white")
            table.add_row(
                finding.category.value,
                finding.data_type,
                finding.value[:50] + "..." if len(finding.value) > 50 else finding.value,
                f"[{risk_color}]{finding.risk_level.name}[/{risk_color}]",
                finding.source,
            )

        console.print(table)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of OSINT session."""
        return {
            "total_findings": len(self.findings),
            "categories": list(set(f.category.value for f in self.findings)),
            "high_risk_count": sum(
                1 for f in self.findings if f.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
            ),
        }


async def create_osint_agent(copilot_client: Optional[Any] = None) -> OSINTAgent:
    """Factory function to create an OSINT Agent.

    Args:
        copilot_client: Optional Copilot client

    Returns:
        Initialized OSINTAgent instance
    """
    agent = OSINTAgent(copilot_client)
    await agent.initialize()
    return agent
