"""
Minka MITRE ATT&CK Matrix - Técnicas de Ataque y Defensa

Matriz completa de MITRE ATT&CK con técnicas, tácticas y contramedidas.
"""

from typing import Dict, Any, List
import random

MITRE_MATRIX = {
    "initial_access": {
        "name": "Initial Access",
        "tactics": [
            "Phishing",
            "External Remote Services",
            "Exploit Public-Facing Application",
            "Drive-by Compromise",
            "Supply Chain Compromise",
            "Trusted Relationship",
            "Valid Accounts",
        ],
        "techniques": {
            "phishing": {
                "name": "Phishing",
                "id": "T1566",
                "description": "Envío de correos maliciosos con links o adjuntos.",
                "examples": [
                    "Spearphishing Attachment",
                    "Spearphishing Link",
                    "Spearphishing via Service",
                ],
                "defense": ["Email Filtering", "User Training", "MFA", "DMARC/DKIM/SPF"],
                "severity": "High",
            },
            "external_remote_services": {
                "name": "External Remote Services",
                "id": "T1133",
                "description": "VPNs, RDP, y otros servicios expuestos a Internet.",
                "examples": ["RDP exposed", "VPN exploitation", "Citrix vulnerabilities"],
                "defense": ["VPN hardening", "MFA", "Network segmentation", "Least privilege"],
                "severity": "High",
            },
            "exploit_public_facing": {
                "name": "Exploit Public-Facing Application",
                "id": "T1190",
                "description": "Explotar vulnerabilidades en aplicaciones web.",
                "examples": ["SQL injection", "XSS", "RCE", "Deserialization"],
                "defense": ["WAF", "Patch management", "Input validation", "DAST scanning"],
                "severity": "Critical",
            },
        },
    },
    "execution": {
        "name": "Execution",
        "tactics": [
            "Command and Scripting Interpreter",
            "Native API",
            "User Execution",
            "Software Exploitation",
            "Scheduled Task/Job",
        ],
        "techniques": {
            "command_interpreter": {
                "name": "Command and Scripting Interpreter",
                "id": "T1059",
                "description": "PowerShell, Bash, Python, Cmd.exe para ejecución.",
                "examples": ["PowerShell.exe", "bash -c", "python script.py"],
                "defense": ["AppLocker", "Constrained Language Mode", "Script logging", "EDR"],
                "severity": "High",
            },
            "scheduled_task": {
                "name": "Scheduled Task/Job",
                "id": "T1053",
                "description": "Tareas programadas para ejecución persistente.",
                "examples": ["at", "schtasks", "cron", "Windows Task Scheduler"],
                "defense": ["Audit scheduled tasks", "Restrict task creation", "MLM detection"],
                "severity": "Medium",
            },
        },
    },
    "persistence": {
        "name": "Persistence",
        "tactics": [
            "Boot or Logon Autostart Execution",
            "Browser Extensions",
            "Compromise Client Software Binary",
            "Create Account",
            "Event Triggered Execution",
            "External Remote Services",
            "Hijack Execution Flow",
            "Modify Authentication Process",
            "Scheduled Task/Job",
        ],
        "techniques": {
            "registry_run_keys": {
                "name": "Boot or Logon Autostart Execution",
                "id": "T1547",
                "description": "Modificar claves de registro para ejecución automática.",
                "examples": [
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Startup folder",
                ],
                "defense": ["Registry monitoring", "AppLocker", "Endpoint hardening"],
                "severity": "High",
            },
            "browsers_extensions": {
                "name": "Browser Extensions",
                "id": "T1176",
                "description": "Extensiones de navegador maliciosas.",
                "examples": ["Chrome extension with data stealing", "Malicious add-on"],
                "defense": ["Restrict extension installation", "Browser security policies"],
                "severity": "Medium",
            },
        },
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "tactics": [
            "Abuse Elevation Control Mechanism",
            "Boot or Logon Autostart Execution",
            "Boot or Logon Initialization Scripts",
            "Create Account",
            "Event Triggered Execution",
            "Exploitation for Privilege Escalation",
            "Hijack Execution Flow",
            "Process Injection",
            "Valid Accounts",
        ],
        "techniques": {
            "process_injection": {
                "name": "Process Injection",
                "id": "T1055",
                "description": "Inyectar código en procesos legítimos.",
                "examples": ["DLL injection", "PE injection", "Reflective loading"],
                "defense": ["EDR", "Process hollowing detection", "Memory protection"],
                "severity": "Critical",
            },
            "exploit_kernel": {
                "name": "Exploitation for Privilege Escalation",
                "id": "T1068",
                "description": "Explotar vulnerabilidades para escalar privilegios.",
                "examples": ["Windows Kernel exploits", "Local privilege escalation CVEs"],
                "defense": ["Patch management", "Kernel hardening", "Credential isolation"],
                "severity": "Critical",
            },
        },
    },
    "defense_evasion": {
        "name": "Defense Evasion",
        "tactics": [
            "Abuse Elevation Control Mechanism",
            "Blind Indicators",
            "Defacement",
            "Hide Artifacts",
            "Impair Defenses",
            "Indicator Removal",
            "Masquerading",
            "Modify Authentication Process",
            "Subvert Trust Controls",
        ],
        "techniques": {
            "disable_security_tools": {
                "name": "Impair Defenses",
                "id": "T1562",
                "description": "Deshabilitar o evadir herramientas de seguridad.",
                "examples": ["Disable Windows Defender", "Stop EDR service", "Kill logging"],
                "defense": ["Tamper detection", "Process monitoring", "Behavioral analysis"],
                "severity": "Critical",
            },
            "clear_logs": {
                "name": "Indicator Removal",
                "id": "T1070",
                "description": "Borrar logs y evidencia.",
                "examples": ["Clear Windows Event Logs", "Delete bash history", "Log tampering"],
                "defense": ["Log centralization", "Immutable backups", "SIEM alerting"],
                "severity": "High",
            },
        },
    },
    "credential_access": {
        "name": "Credential Access",
        "tactics": [
            "Brute Force",
            "Credentials from Password Stores",
            "Discovery of Credentials",
            "Input Capture",
            "Man-in-the-Middle",
            "Unsecured Credentials",
        ],
        "techniques": {
            "mimikatz": {
                "name": "Credentials from Password Stores",
                "id": "T1555",
                "description": "Extraer credenciales de memory, archivos, o sistemas.",
                "examples": ["Mimikatz LSASS", "Keychain dumping", "Credential Manager"],
                "defense": ["Credential Guard", "LSA protection", "MFA everywhere"],
                "severity": "Critical",
            },
            "keylogging": {
                "name": "Input Capture",
                "id": "T1056",
                "description": "Capturar keystrokes y inputs del usuario.",
                "examples": ["Keylogger", "Screen capture", "Clipboard stealing"],
                "defense": ["Endpoint protection", "Input encryption", "Behavioral detection"],
                "severity": "High",
            },
        },
    },
    "discovery": {
        "name": "Discovery",
        "tactics": [
            "Account Discovery",
            "Application Window Discovery",
            "Browser Bookmark Discovery",
            "Cloud Infrastructure Discovery",
            "Cloud Service Dashboard Discovery",
            "Cloud Service Discovery",
            "Container and Resource Discovery",
            "Device Discovery",
            "File and Directory Discovery",
            "Group Policy Discovery",
            "Network Service Scanning",
            "Network Sniffing",
            "Password Policy Discovery",
            "Permission Groups Discovery",
            "Process Discovery",
            "Software Discovery",
            "System Information Discovery",
            "System Network Configuration Discovery",
            "System Owner/User Discovery",
            "System Time Discovery",
        ],
        "techniques": {
            "network_discovery": {
                "name": "Network Service Scanning",
                "id": "T1046",
                "description": "Escanear la red para encontrar servicios.",
                "examples": ["Nmap scan", "NetBIOS enumeration", "SMB discovery"],
                "defense": ["Network segmentation", "IDS/IPS", "NetFlow monitoring"],
                "severity": "Medium",
            },
            "system_info": {
                "name": "System Information Discovery",
                "id": "T1082",
                "description": "Recopilar información del sistema.",
                "examples": ["systeminfo", "hostname", "whoami", "ipconfig"],
                "defense": ["Log commands", "Process auditing", "Least privilege"],
                "severity": "Low",
            },
        },
    },
    "lateral_movement": {
        "name": "Lateral Movement",
        "tactics": [
            "Exploitation of Remote Services",
            "Internal Spearphishing",
            "Lateral Tool Transfer",
            "Remote Services",
            "Replication Through Removable Media",
            "Software Deployment Tools",
            "Use Alternate Authentication Material",
        ],
        "techniques": {
            "psexec": {
                "name": "Remote Services",
                "id": "T1021",
                "description": "Usar servicios remotos para moverse.",
                "examples": ["PsExec", "WMI", "SMB/Admin shares", "RDP"],
                "defense": ["Network segmentation", "MFA for RDP", "Disable SMBv1"],
                "severity": "High",
            },
            "pass_the_hash": {
                "name": "Use Alternate Authentication Material",
                "id": "T1550",
                "description": "Usar hashes de autenticación en lugar de passwords.",
                "examples": ["Pass-the-Hash", "Pass-the-Ticket (Kerberos)", "Over-Pass-the-Hash"],
                "defense": ["Credential Guard", "Limit admin rights", "EDR"],
                "severity": "Critical",
            },
        },
    },
    "collection": {
        "name": "Collection",
        "tactics": [
            "Adversary-in-the-Middle",
            "Archive Collected Data",
            "Audio Capture",
            "Automated Collection",
            "Clipboard Data",
            "Data from Cloud Storage",
            "Data from Configuration Repository",
            "Data from Information Repositories",
            "Data from Local System",
            "Data from Network Shared Drive",
            "Data from Removable Media",
            "Email Collection",
            "Input Capture",
            "Screen Capture",
        ],
        "techniques": {
            "screen_capture": {
                "name": "Screen Capture",
                "id": "T1113",
                "description": "Capturar screenshots del sistema.",
                "examples": ["Desktop screenshot", "Multiple monitor capture"],
                "defense": ["Process monitoring", "Screen capture blocking", "EDR"],
                "severity": "Medium",
            },
            "email_collection": {
                "name": "Email Collection",
                "id": "T1114",
                "description": "Recopilar emails de sistemas comprometidos.",
                "examples": ["Outlook PST extraction", "Exchange compromise", "IMAP access"],
                "defense": ["Email monitoring", "MFA for email", "Data loss prevention"],
                "severity": "High",
            },
        },
    },
    "exfiltration": {
        "name": "Exfiltration",
        "tactics": [
            "Automated Exfiltration",
            "Data Transfer Size Limits",
            "Exfiltration Over Alternative Protocol",
            "Exfiltration Over C2 Channel",
            "Exfiltration Over Physical Medium",
            "Scheduled Transfer",
        ],
        "techniques": {
            "exfil_https": {
                "name": "Exfiltration Over Alternative Protocol",
                "id": "T1048",
                "description": "Exfiltrar datos usando protocolos alternativos.",
                "examples": ["DNS tunneling", "HTTPS exfil", "ICMP tunneling"],
                "defense": ["DLP solutions", "Network monitoring", "DNS logging"],
                "severity": "High",
            },
            "compression": {
                "name": "Archive Collected Data",
                "tactics": ["Collection", "Exfiltration"],
                "id": "T1560",
                "description": "Comprimir datos antes de exfiltrar.",
                "examples": ["ZIP with password", "7z", "Rar"],
                "defense": ["DLP", "File monitoring", "Network traffic analysis"],
                "severity": "Medium",
            },
        },
    },
    "impact": {
        "name": "Impact",
        "tactics": [
            "Account Access Removal",
            "Data Destruction",
            "Data Encrypted for Impact",
            "Data Manipulation",
            "Defacement",
            "Endpoint Denial of Service",
            "Network Denial of Service",
            "Resource Hijacking",
            "Service Stop",
        ],
        "techniques": {
            "ransomware": {
                "name": "Data Encrypted for Impact",
                "id": "T1486",
                "description": "Cifrar datos para extorsion.",
                "examples": ["Ryuk", "LockBit", "CryptoLocker", "WannaCry"],
                "defense": ["Offline backups", "EDR", "Network segmentation"],
                "severity": "Critical",
            },
            "destructive_malware": {
                "name": "Data Destruction",
                "tactics": ["Impact"],
                "id": "T1485",
                "description": "Destruir datos de forma irreversible.",
                "examples": ["Shamoon", "NotPetya", "Kill disk"],
                "defense": ["Immutable backups", "Air gaps", "MLM monitoring"],
                "severity": "Critical",
            },
        },
    },
}

MITRE_GROUPS = {
    "apt29": {
        "name": "APT29 (Cozy Bear)",
        "aliases": ["Cozy Bear", "The Dukes"],
        "attribution": "Russia (SVR)",
        "target_sectors": ["Government", "Think Tanks", "Diplomatic"],
        "techniques": ["T1071", "T1059", "T1003"],
        "description": "Grupo ruso sofisticado asociado con el SVR. Conocido por operaciones de espionaje de larga duración.",
    },
    "apt41": {
        "name": "APT41 (Winnti)",
        "aliases": ["Winnti", "Wicked Panda"],
        "attribution": "China",
        "target_sectors": ["Healthcare", "Gaming", "Software", "Telecom"],
        "techniques": ["T1190", "T1059", "T1055"],
        "description": "Grupo chino único por operar tanto para espionaje estatal como para enriquecimiento personal.",
    },
    "lazarus": {
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "Zinc"],
        "attribution": "North Korea",
        "target_sectors": ["Financial", "Cryptocurrency", "Gaming"],
        "techniques": ["T1486", "T1190", "T1053"],
        "description": "Grupo norcoreano enfocado en financieras, responsable de $1B+ en robos de criptomonedas.",
    },
    "sandworm": {
        "name": "Sandworm Team",
        "aliases": ["Voodoo Bear", "Electrum"],
        "attribution": "Russia (GRU)",
        "target_sectors": ["Energy", "Media", "Government", "Infrastructure"],
        "techniques": ["T1499", "T1561", "T1490"],
        "description": "Grupo ruso responsable de ataques a infraestructura crítica. Caen los sistemas eléctricos de Ukraine.",
    },
    "fin7": {
        "name": "FIN7",
        "aliases": ["Carbanak Group"],
        "attribution": "Russia/Ukraine",
        "target_sectors": ["Retail", "Hospitality", "Financial"],
        "techniques": ["T1566", "T1003", "T1555"],
        "description": "Grupo criminal sofisticado focused en point-of-sale malware y fraude financiero.",
    },
}


async def get_mitre_technique(technique: str, format: str = "brief") -> str:
    """Obtiene información sobre técnicas MITRE ATT&CK."""
    technique_lower = technique.lower()

    for tactic_key, tactic_data in MITRE_MATRIX.items():
        for tech_key, tech_info in tactic_data.get("techniques", {}).items():
            if (
                technique_lower in tech_key.lower()
                or technique_lower in tech_info.get("name", "").lower()
                or technique_lower in tech_info.get("id", "").lower()
            ):
                if format == "brief":
                    return f"""**{tech_info["name"]}** ({tech_info["id"]})

{tech_info["description"]}

**Ejemplos:** {", ".join(tech_info.get("examples", [])[:3])}
**Defensas:** {", ".join(tech_info.get("defense", [])[:3])}
**Severidad:** {tech_info.get("severity", "Medium")}
"""
                elif format == "full":
                    examples = tech_info.get("examples", [])
                    defenses = tech_info.get("defense", [])
                    return f"""## {tech_info["name"]} ({tech_info["id"]})

### Descripción
{tech_info["description"]}

### Táctica
{tactic_data["name"]}

### Ejemplos
{chr(10).join(f"- {ex}" for ex in examples)}

### Contramedidas
{chr(10).join(f"- {defense}" for defense in defenses)}

### Severidad
{tech_info.get("severity", "Medium")}
"""
                elif format == "defense":
                    return f"""## {tech_info["name"]} - Defensas

### Contramedidas Recomendadas
{chr(10).join(f"1. **{defense}**" for defense in tech_info.get("defense", []))}

### Recursos
- MITRE ATT&CK: https://attack.mitre.org/techniques/{tech_info["id"]}
- NIST Cybersecurity Framework
- CIS Controls
"""
                else:
                    return tech_info.get("description", "Technique not found")

    return f"❌ Técnica '{technique}' no encontrada en MITRE ATT&CK. Prueba con: phishing, ransomware, process_injection, psexec, etc."


async def get_mitre_tactic(tactic: str, format: str = "summary") -> str:
    """Obtiene información sobre tácticas MITRE ATT&CK."""
    tactic_lower = tactic.lower()

    for tactic_key, tactic_data in MITRE_MATRIX.items():
        if (
            tactic_lower in tactic_key.lower()
            or tactic_lower in tactic_data.get("name", "").lower()
        ):
            techniques = tactic_data.get("techniques", {})
            if format == "summary":
                return f"""## {tactic_data["name"]}

### Técnicas ({len(techniques)})
{chr(10).join(f"- **{t['name']}** ({t['id']})" for t in techniques.values())}

### Descripción
{", ".join(tactic_data.get("tactics", [])[:3])}...
"""
            else:
                return f"## {tactic_data['name']}\n\n" + chr(10).join(
                    f"**{t['name']}** ({t['id']}): {t['description'][:100]}..."
                    for t in techniques.values()
                )

    return f"Táctica '{tactic}' no encontrada."


async def get_mitre_group(group: str, format: str = "brief") -> str:
    """Obtiene información sobre grupos APT de MITRE."""
    group_lower = group.lower()

    for group_key, group_data in MITRE_GROUPS.items():
        if group_lower in group_key.lower() or group_lower in group_data.get("name", "").lower():
            if format == "brief":
                return f"""**{group_data["name"]}**

Aliases: {", ".join(group_data.get("aliases", []))}
Atribución: {group_data.get("attribution", "Unknown")}
Sectores: {", ".join(group_data.get("target_sectors", []))}

{group_data["description"]}
"""
            elif format == "full":
                return f"""## {group_data["name"]}

### Información General
- **Aliases:** {", ".join(group_data.get("aliases", []))}
- **Atribución:** {group_data.get("attribution", "Unknown")}
- **Sectores Objetivo:** {", ".join(group_data.get("target_sectors", []))}

### Técnicas Usadas
{chr(10).join(f"- {t}" for t in group_data.get("techniques", []))}

### Descripción
{group_data["description"]}
"""
            else:
                return group_data.get("description", "")

    return f"Grupo '{group}' no encontrado. Prueba con: apt29, apt41, lazarus, sandworm, fin7."


async def get_mitre_matrix(format: str = "summary") -> str:
    """Obtiene resumen de toda la matriz MITRE ATT&CK."""
    if format == "summary":
        lines = ["## Matriz MITRE ATT&CK\n"]
        for tactic_key, tactic_data in MITRE_MATRIX.items():
            techniques = tactic_data.get("techniques", {})
            lines.append(f"### {tactic_data['name']}")
            lines.append(f"- {len(techniques)} técnicas documentadas")
            lines.append(f"- Key techniques: {', '.join(list(techniques.keys())[:3])}")
            lines.append("")

        lines.append("## Grupos APT Conocidos")
        for group_key, group_data in MITRE_GROUPS.items():
            lines.append(f"- **{group_data['name']}**: {group_data.get('attribution', 'Unknown')}")

        return "\n".join(lines)
    else:
        return "## Matriz MITRE ATT&CK\n\n" + chr(10).join(
            f"**{tactic_data['name']}**: {len(tactic_data.get('techniques', {}))} técnicas"
            for tactic_key, tactic_data in MITRE_MATRIX.items()
        )
