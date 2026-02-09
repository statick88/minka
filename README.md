# Minka 🛡️

<div align="center">

![Minka - Cybersecurity Assistant](https://img.shields.io/badge/Minka-Cybersecurity%20Assistant-blue?style=for-the-badge)
![Clean Architecture](https://img.shields.io/badge/clean-architecture-purple?style=for-the-badge)
![SOLID Principles](https://img.shields.io/badge/SOLID-principles-orange?style=for-the-badge)
![Python 3.11+](https://img.shields.io/badge/Python-3.11+-green?style=for-the-badge)
![GitHub Copilot SDK](https://img.shields.io/badge/GitHub-Copilot%20SDK-black?style=for-the-badge)

**An AI-powered cybersecurity assistant built with Clean Architecture, SOLID principles, and GitHub Copilot SDK**

[*Español*](README_ES.md) | [*English*](README.md)

</div>

---

## 📖 Overview

Minka is an educational cybersecurity assistant designed for students and professionals in cybersecurity. It leverages **GitHub Copilot SDK** to provide intelligent assistance for:

- 🔍 **Vulnerability Research** - CVE analysis and security research
- 🛡️ **Red Team Operations** - Ethical pentesting methodologies
- 🔎 **OSINT Gathering** - Open source intelligence collection
- 🏗️ **Secure Architecture** - Clean Architecture and SOLID principles

> **Note**: Minka is an educational project for the [Máster en Ciberseguridad Defensiva y Ofensiva](https://www.masterciberseguridaducm.com/) at Universidad Complutense de Madrid (UCM).

---

## 🏛️ Architecture

Minka follows **Robert C. Martin (Uncle Bob)** principles:

### The Clean Architecture Pyramid

```
                    ┌─────────────────────────────┐
                    │     Enterprise Business      │
                    │       (Use Cases)          │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │     Application Business     │
                    │        (Services)          │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │     Domain Business Logic   │
                    │         (Entities)         │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │     Framework & Tools     │
                    │  (DB, Web, External APIs)  │
                    └─────────────────────────────┘

              ⬆️ All dependencies point inward ⬆️
```

### SOLID Principles

| Principle | Description | Status |
|-----------|-------------|--------|
| **SRP** | Single Responsibility | ✅ Applied |
| **OCP** | Open/Closed | ✅ Applied |
| **LSP** | Liskov Substitution | ✅ Applied |
| **ISP** | Interface Segregation | ✅ Applied |
| **DIP** | Dependency Inversion | ✅ Applied |

---

## 🎯 Features

### Core Capabilities

- 🤖 **AI-Powered Assistance** - Built on GitHub Copilot SDK
- 📚 **Educational Focus** - Learn cybersecurity safely
- 🔧 **Tool Integration** - Nmap, CVE databases, vulnerability scanners
- 📊 **Lab Environments** - DVWA, OWASP Juice Shop, WebGoat
- 🎓 **UCM Aligned** - Aligned with cybersecurity master curriculum

### Available Agents

| Agent | Purpose | Specialization |
|-------|---------|----------------|
| **Vulnerability Researcher** | CVE analysis, PoC generation | Primary |
| **Red Team Specialist** | Ethical pentesting, MITRE ATT&CK | Offensive |
| **OSINT Investigator** | Passive reconnaissance, intelligence | Intelligence |
| **Security Architect** | Clean Architecture, secure design | Defensive |

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- GitHub Copilot subscription (GitHub Education recommended)
- Python 3.11+

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/minka.git
cd minka

# Configure environment
cp docker/.env.example docker/.env
# Edit docker/.env with your GITHUB_TOKEN

# Start with Docker
docker-compose -f docker/docker-compose.yml up -d

# Or run locally
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start Minka
minka start
```

### Usage

```bash
# Interactive mode
minka start

# Scan a target
minka scan --target example.com

# Analyze code
minka analyze --target ./vulnerable_code.py

# Start a lab
minka lab start dvwa
```

---

## 📁 Project Structure

```
minka/
├── docker/                    # Docker configuration
│   ├── Dockerfile.minka       # Main application image
│   ├── Dockerfile.labs         # Lab environments
│   └── docker-compose.yml      # Multi-container setup
│
├── src/                        # Application source code
│   ├── core/                  # Domain and application layers
│   │   ├── client.py          # GitHub Copilot SDK wrapper
│   │   ├── config.py          # Configuration management
│   │   └── session.py         # Session management
│   │
│   ├── agents/                # Specialized agents
│   │   ├── vuln_researcher/   # Vulnerability research
│   │   ├── red_team/          # Red team operations
│   │   ├── osint/             # OSINT gathering
│   │   └── security_architect/ # Architecture design
│   │
│   ├── tools/                 # Security tools integration
│   │   ├── nmap_integration.py
│   │   ├── security_tools.py
│   │   └── mcp_tools.py
│   │
│   └── cli/                   # Command-line interface
│       ├── main.py
│       ├── commands/
│       └── ui/
│
├── labs/                       # Vulnerable lab environments
│   ├── dvwa/                  # Damn Vulnerable Web App
│   ├── juice-shop/            # OWASP Juice Shop
│   └── webgoat/               # OWASP WebGoat
│
├── tests/                      # Test suite
│   ├── unit/
│   ├── integration/
│   └── security/
│
├── docs/                       # Documentation
│   ├── api/
│   ├── guides/
│   └── TFM-PROPUESTA.md
│
├── .github/copilot/           # GitHub Copilot configuration
│   ├── instructions.md         # Master instructions
│   ├── skills/                # Agent skills
│   └── agents/                # Agent configurations
│
├── scripts/                    # Utility scripts
├── pyproject.toml             # Python project configuration
├── requirements.txt            # Python dependencies
├── README.md                  # This file
└── LICENSE                    # MIT License
```

---

## 📚 Documentation

### For Users

- [Installation Guide](docs/installation.md)
- [User Manual](docs/usage.md)
- [CLI Reference](docs/cli-reference.md)
- [Lab Environments](docs/labs.md)

### For Developers

- [Architecture Guide](docs/architecture.md)
- [API Documentation](docs/api/README.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Code Style Guide](docs/style-guide.md)

### For Researchers

- [TFM Proposal](docs/TFM-PROPUESTA.md)
- [Research Methodology](docs/research.md)
- [Publications](docs/publications.md)

---

## 🎓 Educational Alignment

Minka is designed for the **Máster en Ciberseguridad Defensiva y Ofensiva** at UCM:

| Master Module | Minka Component |
|---------------|----------------|
| **IA aplicada a Ciberseguridad** | GitHub Copilot SDK integration |
| **Operaciones - Red Team** | Red Team Agent, pentesting tools |
| **Herramientas de Ciberseguridad** | Tool integration, CVE lookup |
| **Criptografía** | Cryptographic analysis |
| **OSINT** | OSINT Investigator Agent |
| **DFIR** | Forensic analysis tools |

---

## 🛡️ Professional Ethics

Minka follows **The Clean Coder** professional standards:

### Our Oath

```
I will not be the cause of harm.
I will produce clean, tested code.
I will continuously improve my craft.
I will share my knowledge freely.
I will respect those before me.
I will help those who follow.
```

### Ethical Guidelines

- ✅ Always emphasize legal and authorized use
- ✅ Focus on defense and mitigation
- ✅ Never generate harmful code
- ✅ Report findings responsibly
- ✅ Protect sensitive information

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

### Ways to Contribute

- 🐛 Report bugs
- 💡 Suggest features
- 📝 Improve documentation
- 🔧 Submit pull requests
- 📚 Share your knowledge

---

## 📖 References

### Books (Robert C. Martin)

1. Martin, R. C. (2017). *Clean Architecture*. Prentice Hall.
2. Martin, R. C. (2008). *Clean Code*. Prentice Hall.
3. Martin, R. C. (2011). *The Clean Coder*. Prentice Hall.
4. Martin, R. C. (2003). *Agile Software Development*. Prentice Hall.

### Academic Sources

- OWASP Foundation. (2024). *OWASP Top 10*.
- MITRE Corporation. (2024). *MITRE ATT&CK Framework*.
- NIST. (2024). *Cybersecurity Framework*.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Universidad Complutense de Madrid](https://www.ucm.es/) - For the cybersecurity master program
- [GitHub](https://github.com/) - For the amazing Copilot SDK
- [Robert C. Martin](https://sites.google.com/site/unclebob/) - For timeless software craftsmanship principles
- [OWASP](https://owasp.org/) - For open-source security resources

---

<div align="center">

**Built with 🛡️ Clean Architecture and 🤖 GitHub Copilot**

*Last updated: February 2026*

</div>
