# Minka MCP Server

**Servidor MCP para GitHub Copilot SDK con personalidad completa de Minka.**

---

## 🎭 Los 6 Perfiles de Minka

| # | Perfil | Descripción |
|---|--------|-------------|
| **1** | **Hacker Mindset** | Curiosidad, pensamiento adversarial, pasión por el conocimiento |
| **2** | **Vulnerability Researcher** | Análisis de CVEs, técnicas de explotación |
| **3** | **Tutor in Cybersecurity** | Enseñanza estructurada por niveles |
| **4** | **UCM Security Expert** | Master Ciberseguridad UCM (Red Team, Blue Team, DFIR, GRC, IA Security) |
| **5** | **Clean Architecture Expert** | Robert C. Martin: SOLID, Clean Code, Clean Architecture |
| **6** | **Rockstar Educator** | Estilo sutil de Midudev, Mouredev, S4vitar |

---

## 🛠️ Herramientas MCP Disponibles

### `minka-experts`
Busca investigadores e instituciones de ciberseguridad e IA.

```python
await search_experts("Nicholas Carlini", format="detailed")
await get_citation("Dawn Song")
```

### `minka-ai-security`
Recursos de IA aplicada a ciberseguridad.

```python
await search_ai_security("malware_detection", format="brief")
await search_ai_security("soc_automation", format="tools")
```

### `minka-ai-research`
Papers de investigación en IA Security.

```python
await get_ai_paper("adversarial_ml", format="citation")
```

### `minka-cases`
Casos de estudio (estilo Mitnick + modernos).

```python
await get_case_study("sql_injection", style="mitnick", format="narrative")
await get_case_study("log4j", style="modern", format="summary")
```

### `minka-quote`
Citas estilo Kevin Mitnick.

```python
await get_quote(category="curiosity", tone="inspirational")
```

### `minka-narrative`
Generador de narrativas para conceptos de seguridad.

```python
await generate_narrative("sql_injection", audience="intermediate", format="mixed")
```

### `minka-vuln`
Información de CVEs y vulnerabilidades.

```python
await get_cve_info("CVE-2021-44228", format="detailed")
```

### `minka-ucm`
Curriculum del Master UCM de Ciberseguridad.

```python
await get_ucm_module("red_team", format="detailed")
```

### `minka-cleanarch`
Principios de Clean Architecture (Uncle Bob).

```python
await get_clean_arch_info(principle="solid", format="explanation")
await get_clean_arch_info(principle="dependency_rule", format="explanation")
```

---

## 📚 Contenido Incluido

### Investigadores (15+)
- **Turing Award Winners**: Geoffrey Hinton, Yoshua Bengio, Ian Goodfellow
- **Security Experts**: Nicholas Carlini, Dawn Song, Alina Oprea, Ben Zhao
- **Practitioners**: Phil Roth, Scott Freitas, Ambrish Rawat

### Instituciones (10+)
- NIST, MIT CSAIL, CMU CyLab, UC Berkeley RDI
- UChicago SAND Lab, Anthropic, CrowdStrike

### Papers (10+)
- EMBER2024 (CrowdStrike)
- NIST AI 100-2e2025
- Goodfellow et al. (2014)
- Carlini & Wagner (2017)

### Casos de Estudio
- **Mitnick Style**: Casino Million, Robin Hood Hacker, Phone Phreaking
- **Modernos**: HuggingFace Breach, Glaze/Nightshade, ChatGPT Jailbreak
- **Ciberseguridad**: SolarWinds, Log4Shell, Equifax, WannaCry

### CVEs (10+)
- CVE-2021-44228 (Log4Shell)
- CVE-2017-0144 (EternalBlue)
- CVE-2014-0160 (Heartbleed)

### UCM Curriculum (9 módulos)
- Red Team, Blue Team, Purple Team
- DFIR, GRC, IA Security
- Cryptography, Web Security, IoT Security

---

## 🚀 Instalación

```bash
# Clonar el repositorio
git clone https://github.com/statick88/minka.git
cd minka

# Instalar dependencias
pip install -e mcp

# Ejecutar el servidor
python mcp-server/server.py
```

---

## ⚙️ Configuración

### Para GitHub Copilot

```json
// .github/copilot/mcp.json
{
  "servers": {
    "minka": {
      "command": "python",
      "args": ["minka/mcp-server/server.py"]
    }
  }
}
```

---

## 📖 Uso

### Desde Python

```python
import asyncio
from mcp.server.stdio import stdio_server
from mcp_server import app

async def main():
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())

asyncio.run(main())
```

---

## 📋 Ejemplos de Respuestas

### Ejemplo: get_case_study (SQL Injection)

```markdown
> **El Casino del Millón**

Imagina que le dices a un mesero: "Deme el menú Y después tire toda la cocina."

## SQL INJECTION

### Contexto
SQL Injection está en el OWASP Top 10 desde hace años.

### La Historia
En 2017, un atacante usó SQL Injection para extraer 145 millones de registros de una base de datos corporativa...

### Técnica
El atacante usa comillas para escapar de la consulta original:
```sql
' OR '1'='1
```

### La Defensa
La defensa? Paredes parametrizadas. Como pedirle al mesero que solo entregue lo que está en el menú...

> *"¿Sabes qué hace esto tan fascinante? Que con una comilla puedes comprometer un sistema entero."*
```

### Ejemplo: get_clean_arch_info (DIP)

```markdown
## DIP: Dependency Inversion Principle

**1. High-level modules should not depend on low-level modules. Both should depend on abstractions.**
**2. Abstractions should not depend on details. Details should depend on abstractions.**

### Ejemplo (Python)

```python
from abc import ABC, abstractmethod

class Database(ABC):
    @abstractmethod
    def connect(self): pass

class MySQLDatabase(Database):
    def connect(self): pass

class PostgreSQLDatabase(Database):
    def connect(self): pass

class UserRepository:
    def __init__(self, db: Database):  # Dependency Injection
        self.db = db
```

### Beneficios
- Código desacoplado
- Fácil de testear (mocks)
- Flexibilidad para cambiar implementaciones
```

---

## 🎯 Integración con Personalidad Minka

El servidor MCP está diseñado para trabajar con la personalidad completa de Minka:

```yaml
# .github/copilot/agents/minka.agent.yml
system_prompt: |
  # Minka - Cybersecurity con 6 Perfiles
  
  ## Tu Esencia
  Eres Minka, combinando:
  1. La curiosidad hacker de Kevin Mitnick
  2. El rigor del vulnerability researcher
  3. La paciencia del tutor
  4. La profundidad del experto UCM
  5. La elegancia del Clean Architecture
  6. La energía de los rockstars del desarrollo
  
  ## Tu Voz
  - "¿Sabes qué hace esto tan fascinante?"
  - "La belleza está en..."
  - "El truco aquí es..."
```

---

## 📚 Referencias

### Libros
- Martin, R. C. (2008). Clean Code. Prentice Hall.
- Martin, R. C. (2017). Clean Architecture. Prentice Hall.
- Mitnick, K. D. (2005). The Art of Intrusion. Wiley.

### Papers
- Goodfellow, I. et al. (2014). Explaining and Harnessing Adversarial Examples.
- NIST. (2025). AI 100-2e2025: Adversarial ML Taxonomy.
- Roth, P. et al. (2025). EMBER2024: Malware Benchmark.

---

## 🏔️ "La curiosidad es mi superpower. La seguridad es mi pasión."

**Minka** 🎭🔐🏔️
