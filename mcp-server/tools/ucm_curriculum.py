"""
Minka UCM Curriculum - Master en Ciberseguridad UCM

Curriculum del Master en Ciberseguridad Defensiva y Ofensiva de la Universidad Complutense de Madrid.
"""

# ============================================
# MÓDULOS DEL MASTER UCM
# ============================================

UCM_MODULES = {
    "red_team": {
        "name": "Red Team",
        "full_name": "Ataques y Técnicas de Intrusión",
        "description": "Enfoque ofensivo: penetration testing, exploitation, y técnicas de ataque.",
        "topics": [
            "Ciberataques reales y metodología",
            "Penetración de sistemas",
            "Explotación de vulnerabilidades",
            "Metodologías PTES",
            "Bug bounty y CTFs",
            "Ingeniería social",
            "Movement lateral",
            "Persistencia",
        ],
        "tools": [
            "Metasploit Framework",
            "Burp Suite",
            "Nmap",
            "Wireshark",
            "Aircrack-ng",
            "John the Ripper",
            "Hashcat",
            "Responder",
            "BloodHound",
            "Cobalt Strike",
        ],
        "frameworks": [
            "OWASP Testing Guide",
            "MITRE ATT&CK",
            "PTES (Penetration Testing Execution Standard)",
            "OSSTMM",
        ],
        "techniques": [
            "Reconnaissance activo y pasivo",
            "Scanning y enumeration",
            "Vulnerability assessment",
            "Exploit development",
            "Privilege escalation",
            "Pivoting",
            "Covering tracks",
        ],
        "references": [
            "The Art of Intrusion (Mitnick)",
            "The Art of Deception (Mitnick)",
            "Pentester Academy",
            "Offensive Security courses",
        ],
    },
    "blue_team": {
        "name": "Blue Team",
        "full_name": "Defensa y Detección",
        "description": "Enfoque defensivo: hardening, monitoring, y respuesta a incidentes.",
        "topics": [
            "Defensa de sistemas",
            "Detección de amenazas",
            "Respuesta a incidentes",
            "Hardening de sistemas",
            "SIEM y logging",
            "Threat hunting",
            "Incident handling",
            "Malware analysis",
        ],
        "tools": [
            "Splunk",
            "ELK Stack (Elasticsearch, Logstash, Kibana)",
            "OSSEC",
            "Wazuh",
            "Zeek (Bro)",
            "Suricata",
            "YARA",
            "Volatility",
            "Autopsy",
            "FTK Imager",
        ],
        "frameworks": [
            "NIST Cybersecurity Framework",
            "CIS Controls",
            "ISO 27001",
            "MITRE ATT&CK",
            "NIST SP 800-61",
            "IOC (Indicators of Compromise)",
        ],
        "techniques": [
            "Security monitoring",
            "Log analysis",
            "Network traffic analysis",
            "Endpoint detection",
            "Malware analysis",
            "Memory forensics",
            "Disk forensics",
            "Incident response",
        ],
        "references": ["NIST Cybersecurity Framework", "SANS DFIR", "Blue Team Labs"],
    },
    "purple_team": {
        "name": "Purple Team",
        "full_name": "Integración Red Team / Blue Team",
        "description": "Enfoque colaborativo: unir capacidades ofensivas y defensivas.",
        "topics": [
            "Integración Red/Blue",
            "Simulaciones de ataque",
            "Threat Intelligence",
            "Feedback loops",
            "Adversary emulation",
            "Validation de controles",
            "Red teaming continuo",
        ],
        "approach": [
            "ATAQUE → DETECCIÓN → MEJORA",
            "Collaborative testing",
            "Continuous improvement",
            "Shared visibility",
        ],
        "tools": ["Caldera (MITRE)", "Atomic Red Team", "Infection Monkey", "SafeBreach"],
        "frameworks": ["MITRE ATT&CK", "Cyber Kill Chain", "NIST CSF"],
        "references": ["MITRE Caldera documentation", "Purple Team exercises"],
    },
    "dfir": {
        "name": "DFIR",
        "full_name": "Digital Forensics & Incident Response",
        "description": "Forensics digital y respuesta a incidentes.",
        "topics": [
            "Digital Forensics",
            "Incident Response",
            "Malware Analysis",
            "Memory Forensics",
            "Network Forensics",
            "Disk Forensics",
            "Cloud Forensics",
            "Mobile Forensics",
        ],
        "tools": [
            "Volatility Framework",
            "FTK Imager",
            "Autopsy",
            "The Sleuth Kit",
            "Zeek",
            "Wireshark",
            " plaso",
            "Autopsy",
            "Cellebrite",
            "Magnet AXIOM",
        ],
        "frameworks": ["NIST SP 800-61", "SANS DFIR methodology", "Evidence handling procedures"],
        "process": [
            "1. Preparation",
            "2. Identification",
            "3. Containment",
            "4. Eradication",
            "5. Recovery",
            "6. Lessons Learned",
        ],
        "references": ["SANS DFIR courses", "NIST SP 800-61", "Malware Analysis books"],
    },
    "grc": {
        "name": "GRC",
        "full_name": "Governance, Risk & Compliance",
        "description": "Gobernanza, gestión de riesgos y cumplimiento.",
        "topics": [
            "Gobernanza de seguridad",
            "Gestión de riesgos",
            "Cumplimiento normativo",
            "Auditorías de seguridad",
            "Política de seguridad",
            "Continuity planning",
            "Vendor risk management",
            "Security awareness",
        ],
        "standards": [
            "ISO 27001",
            "ISO 27002",
            "NIST CSF",
            "NIST SP 800-53",
            "GDPR (Europe)",
            "LOPDGDD (Spain)",
            "PCI DSS",
            "HIPAA",
            "SOC 2",
        ],
        "frameworks": ["NIST Cybersecurity Framework", "ISO 27001/27002", "COSO", "COBIT"],
        "tools": ["GRC platforms", "Risk assessment tools", "Compliance management systems"],
        "references": ["ISO 27001:2022", "NIST CSF", "ISACA materials"],
    },
    "ia_security": {
        "name": "IA Security",
        "full_name": "Inteligencia Artificial Aplicada a Ciberseguridad",
        "description": "IA/ML para seguridad y seguridad de sistemas IA.",
        "topics": [
            "Machine Learning para detección de amenazas",
            "Adversarial ML",
            "ML para anomaly detection",
            "AI Red Teaming",
            "Seguridad de LLMs",
            "Prompt injection",
            "Generative AI security",
        ],
        "papers": [
            "EMBER2024 (CrowdStrike)",
            "NIST AI 100-2e2025",
            "Goodfellow et al. (2014)",
            "Carlini & Wagner (2017)",
        ],
        "tools": [
            "EMBER benchmark",
            "Microsoft Counterfit",
            "NVIDIA Morpheus",
            "Microsoft Copilot for Security",
        ],
        "techniques": [
            "Static malware analysis con ML",
            "Dynamic analysis con ML",
            "Anomaly detection",
            "Threat intelligence automation",
        ],
        "references": [
            "EMBER: https://github.com/elastic/ember",
            "NIST AI 100-2e2025",
            "arXiv papers",
        ],
    },
    "cryptography": {
        "name": "Cryptography",
        "full_name": "Criptografía Práctica",
        "description": "Criptografía aplicada a la seguridad.",
        "topics": [
            "Criptografía simétrica",
            "Criptografía asimétrica",
            "Funciones hash",
            "PKI (Infraestructura de Clave Pública)",
            "Protocolos seguros",
            "TLS/SSL",
            "VPNs",
            "Digital signatures",
            "Zero Knowledge Proofs",
            "Homomorphic encryption",
        ],
        "algorithms": [
            "Symmetric: AES, ChaCha20",
            "Asymmetric: RSA, ECC, Ed25519",
            "Hashing: SHA-256, SHA-3, BLAKE3",
            "Key exchange: ECDH, X25519",
            "AEAD: AES-GCM, ChaCha20-Poly1305",
        ],
        "protocols": ["TLS 1.3", "Signal Protocol", "OAuth 2.0", "OpenID Connect", "JWT"],
        "tools": ["OpenSSL", "GnuPG", "Let's Encrypt", "HashiCorp Vault", "WireGuard"],
        "references": [
            "Applied Cryptography (Schneier)",
            "Serious Cryptography (Aumasson)",
            "Crypto Stack Exchange",
        ],
    },
    "web_security": {
        "name": "Web Security",
        "full_name": "Seguridad de Aplicaciones Web",
        "description": "Seguridad web y desarrollo seguro.",
        "topics": [
            "OWASP Top 10",
            "Secure coding",
            "API security",
            "Authentication/Authorization",
            "Session management",
            "Input validation",
            "Output encoding",
            "Business logic security",
        ],
        "tools": ["OWASP ZAP", "Burp Suite", "Nuclei", "Nikto", "Subfinder", "Amass"],
        "owasp_top_10": [
            "A01:2021 - Broken Access Control",
            "A02:2021 - Cryptographic Failures",
            "A03:2021 - Injection",
            "A04:2021 - Insecure Design",
            "A05:2021 - Security Misconfiguration",
            "A06:2021 - Vulnerable Components",
            "A07:2021 - Auth Failures",
            "A08:2021 - Data Integrity",
            "A09:2021 - Logging Failures",
            "A10:2021 - SSRF",
        ],
        "references": [
            "OWASP Testing Guide",
            "OWASP ASVS",
            "OWASP SAMM",
            "Web Security Academy (PortSwigger)",
        ],
    },
    "iot_security": {
        "name": "IoT Security",
        "full_name": "Seguridad de IoT y Dispositivos",
        "description": "Seguridad de dispositivos conectados y sistemas embebidos.",
        "topics": [
            "Seguridad de dispositivos IoT",
            "Protocolos IoT",
            "Hardware security",
            "Embedded systems",
            "Firmware analysis",
            "Radio frequency security",
            "Bluetooth/BLE security",
            "Zigbee security",
            "MQTT security",
            "Device attestation",
        ],
        "tools": [
            "Ghidra",
            "IDA Pro",
            "Binwalk",
            "Firmware Mod Kit",
            "UART/JTAG tools",
            "Saleae Logic",
            "HackRF",
            "RTL-SDR",
        ],
        "protocols": ["MQTT", "CoAP", "Zigbee", "Z-Wave", "Bluetooth LE", "WiFi", "Thread"],
        "techniques": [
            "Firmware extraction",
            "Reverse engineering",
            "Side-channel attacks",
            "Fuzzing embebido",
            "Radio analysis",
        ],
        "references": ["IoT Security Foundation", "OWASP IoT Top 10", "Hardware hacking books"],
    },
}

# ============================================
# HERRAMIENTAS GENERALES DEL MASTER
# ============================================

MASTER_TOOLS = {
    "reconnaissance": {
        "tools": ["Nmap", "Masscan", "Subfinder", "Amass", "Maltego", "Shodan", "Censys"],
        "description": "Descubrimiento de superficie de ataque",
    },
    "scanning": {
        "tools": ["Nessus", "OpenVAS", "Nikto", "Qualys"],
        "description": "Escaneo de vulnerabilidades",
    },
    "exploitation": {
        "tools": ["Metasploit", "Cobalt Strike", "PowerShell Empire", " Covenant"],
        "description": "Frameworks de explotación",
    },
    "web_testing": {
        "tools": ["Burp Suite", "OWASP ZAP", "SQLMap", "XSSer", "wfuzz"],
        "description": "Testing de aplicaciones web",
    },
    "password_attacks": {
        "tools": ["Hashcat", "John the Ripper", "Hydra", "Medusa", "CrackMapExec"],
        "description": "Ataques de contraseña",
    },
    "forensics": {
        "tools": ["Volatility", "FTK Imager", "Autopsy", "Zeek", "Wireshark"],
        "description": "Análisis forense",
    },
    "reverse_engineering": {
        "tools": ["Ghidra", "IDA Pro", "Radare2", "Binary Ninja", "Hopper"],
        "description": "Ingeniería inversa",
    },
    "reporting": {
        "tools": ["Dradis", "Faraday", "Maltego", "KeepNote"],
        "description": "Gestión de hallazgos y reportes",
    },
}

# ============================================
# CERTIFICACIONES RELACIONADAS
# ============================================

CERTIFICATIONS = {
    "offensive": [
        "OSCP (Offensive Security)",
        "OSEP (Offensive Security)",
        "OSCE3 / OSWE (Offensive Security)",
        "GPEN (SANS)",
        "CPEH (EC-Council)",
    ],
    "defensive": [
        "GCFE (SANS)",
        "GREM (SANS)",
        "GCFA (SANS)",
        "CySA+ (CompTIA)",
        "CHFI (EC-Council)",
    ],
    "management": ["CISM (ISACA)", "CISO (EC-Council)", "CRISC (ISACA)", "CISSP (ISC²)"],
    "cloud": [
        "CCSP (ISC²)",
        "CCSK (Cloud Security Alliance)",
        "AWS Security Specialty",
        "Azure Security Engineer",
    ],
}

# ============================================
# FUNCIONES
# ============================================


async def get_ucm_module(module: str, format: str = "summary") -> str:
    """Obtiene información de un módulo del Master UCM."""

    module_lower = module.lower()

    # Buscar módulo
    for key, mod in UCM_MODULES.items():
        if module_lower in key or module_lower in mod["name"].lower():
            return format_ucm_module(mod, key, format)

    return f"""❌ Módulo '{module}' no encontrado.

**Módulos disponibles:**
- red_team: Ataques y técnicas de intrusión
- blue_team: Defensa y detección
- purple_team: Integración Red/Blue
- dfir: Digital Forensics & Incident Response
- grc: Governance, Risk & Compliance
- ia_security: IA aplicada a ciberseguridad
- cryptography: Criptografía práctica
- web_security: Seguridad de aplicaciones web
- iot_security: Seguridad de IoT"""


def format_ucm_module(mod: dict, key: str, format: str) -> str:
    """Formatea información de un módulo."""

    if format == "summary":
        return f"""## {mod["name"]}

**{mod["full_name"]}**

{mod["description"]}

**Temas principales:**
{chr(10).join(f"- {t}" for t in mod["topics"][:5])}

**Herramientas:**
{chr(10).join(f"- {t}" for t in mod.get("tools", [])[:5])}"""

    elif format == "tools":
        return f"""## {mod["name"]} - Herramientas

{mod["description"]}

**Herramientas:**
{chr(10).join(f"- {t}" for t in mod.get("tools", []))}

**Frameworks:**
{chr(10).join(f"- {f}" for f in mod.get("frameworks", []))}"""

    else:  # detailed
        lines = [
            f"## {mod['name']}",
            f"**{mod['full_name']}**",
            "",
            "### Descripción",
            mod["description"],
            "",
            "### Temas",
            chr(10).join(f"- {t}" for t in mod["topics"]),
            "",
        ]

        if "tools" in mod:
            lines.extend(["### Herramientas", chr(10).join(f"- {t}" for t in mod["tools"]), ""])

        if "frameworks" in mod:
            lines.extend(["### Frameworks", chr(10).join(f"- {f}" for f in mod["frameworks"]), ""])

        if "techniques" in mod:
            lines.extend(["### Técnicas", chr(10).join(f"- {t}" for t in mod["techniques"]), ""])

        if "references" in mod:
            lines.extend(["### Referencias", chr(10).join(f"- {r}" for t in mod["references"]), ""])

        return "\n".join(lines)


async def get_all_modules() -> str:
    """Lista todos los módulos del Master."""

    lines = ["# Master en Ciberseguridad UCM - Módulos", ""]

    for key, mod in UCM_MODULES.items():
        lines.append(f"## {mod['name']}")
        lines.append(f"{mod['description']}")
        lines.append("")

    return "\n".join(lines)
