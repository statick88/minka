# Minka 🛡️

<div align="center">

![Minka - Cybersecurity Assistant](https://img.shields.io/badge/Minka-Cybersecurity%20Assistant-blue?style=for-the-badge)
![Clean Architecture](https://img.shields.io/badge/clean-architecture-purple?style=for-the-badge)
![SOLID Principles](https://img.shields.io/badge/SOLID-principles-orange?style=for-the-badge)
![Python 3.11+](https://img.shields.io/badge/Python-3.11+-green?style=for-the-badge)
![GitHub Copilot SDK](https://img.shields.io/badge/GitHub-Copilot%20SDK-black?style=for-the-badge)

**Asistente de ciberseguridad construido con Clean Architecture, principios SOLID y GitHub Copilot SDK**

[*English*](README.md) | [*Español*](README_ES.md)

</div>

---

## 📖 Descripción General

Minka es un asistente educativo de ciberseguridad diseñado para estudiantes y profesionales. Utiliza **GitHub Copilot SDK** para proporcionar asistencia inteligente en:

- 🔍 **Investigación de Vulnerabilidades** - Análisis de CVEs e investigación de seguridad
- 🛡️ **Operaciones Red Team** - Metodologías de pentesting ético
- 🔎 **OSINT** - Recolección de inteligencia de fuentes abiertas
- 🏗️ **Arquitectura Segura** - Clean Architecture y principios SOLID

> **Nota**: Minka es un proyecto educativo para el [Máster en Ciberseguridad Defensiva y Ofensiva](https://www.masterciberseguridaducm.com/) de la Universidad Complutense de Madrid (UCM).

---

## 🏛️ Arquitectura

Minka sigue los principios de **Robert C. Martin (Uncle Bob)**:

### Pirámide de Clean Architecture

```
                    ┌─────────────────────────────┐
                    │     Reglas de Negocio       │
                    │       (Casos de Uso)        │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │     Lógica de Aplicación   │
                    │       (Servicios)          │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │     Lógica de Dominio     │
                    │       (Entidades)         │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │    Herramientas y Frameworks│
                    │  (DB, Web, APIs Externas) │
                    └─────────────────────────────┘

              ⬆️ Todas las dependencias apuntan hacia adentro ⬆️
```

### Principios SOLID

| Principio | Descripción | Estado |
|-----------|-------------|--------|
| **SRP** | Responsabilidad Única | ✅ Aplicado |
| **OCP** | Abierto/Cerrado | ✅ Aplicado |
| **LSP** | Sustitución de Liskov | ✅ Aplicado |
| **ISP** | Segregación de Interfaces | ✅ Aplicado |
| **DIP** | Inversión de Dependencias | ✅ Aplicado |

---

## 🎯 Características

### Capacidades Principales

- 🤖 **Asistencia IA** - Construido sobre GitHub Copilot SDK
- 📚 **Enfoque Educativo** - Aprende ciberseguridad de forma segura
- 🔧 **Integración de Herramientas** - Nmap, bases de datos CVE, escáneres
- 📊 **Entornos de Laboratorio** - DVWA, OWASP Juice Shop, WebGoat
- 🎓 **Alineado con UCM** - Alineado con el currículo del máster

### Agentes Disponibles

| Agente | Propósito | Especialización |
|--------|-----------|-----------------|
| **Investigador de Vulnerabilidades** | Análisis de CVEs, generación de PoCs | Primario |
| **Especialista Red Team** | Pentesting ético, MITRE ATT&CK | Ofensivo |
| **Investigador OSINT** | Reconocimiento pasivo, inteligencia | Inteligencia |
| **Arquitecto de Seguridad** | Clean Architecture, diseño seguro | Defensivo |

---

## 🚀 Inicio Rápido

### Prerrequisitos

- Docker y Docker Compose
- Suscripción a GitHub Copilot (GitHub Education recomendado)
- Python 3.11+

### Instalación

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/minka.git
cd minka

# Configurar entorno
cp docker/.env.example docker/.env
# Editar docker/.env con tu GITHUB_TOKEN

# Iniciar con Docker
docker-compose -f docker/docker-compose.yml up -d

# O ejecutar localmente
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt

# Iniciar Minka
minka start
```

### Uso

```bash
# Modo interactivo
minka start

# Escanear un objetivo
minka scan --target ejemplo.com

# Analizar código
minka analyze --target ./codigo_vulnerable.py

# Iniciar un laboratorio
minka lab start dvwa
```

---

## 📁 Estructura del Proyecto

```
minka/
├── docker/                    # Configuración Docker
│   ├── Dockerfile.minka       # Imagen principal
│   ├── Dockerfile.labs        # Entornos de laboratorio
│   └── docker-compose.yml     # Configuración multi-contenedor
│
├── src/                        # Código fuente
│   ├── core/                  # Capa de dominio y aplicación
│   │   ├── client.py          # Wrapper de GitHub Copilot SDK
│   │   ├── config.py          # Gestión de configuración
│   │   └── session.py         # Gestión de sesiones
│   │
│   ├── agents/                # Agentes especializados
│   │   ├── vuln_researcher/   # Investigación de vulnerabilidades
│   │   ├── red_team/         # Operaciones Red Team
│   │   ├── osint/            # Recolección OSINT
│   │   └── security_architect/ # Diseño de arquitectura
│   │
│   ├── tools/                 # Integración de herramientas
│   │   ├── nmap_integration.py
│   │   ├── security_tools.py
│   │   └── mcp_tools.py
│   │
│   └── cli/                   # Interfaz de línea de comandos
│       ├── main.py
│       ├── commands/
│       └── ui/
│
├── labs/                       # Entornos de laboratorio vulnerables
│   ├── dvwa/                  # Damn Vulnerable Web App
│   ├── juice-shop/            # OWASP Juice Shop
│   └── webgoat/               # OWASP WebGoat
│
├── tests/                      # Suite de pruebas
│   ├── unit/
│   ├── integration/
│   └── security/
│
├── docs/                       # Documentación
│   ├── api/
│   ├── guides/
│   └── TFM-PROPUESTA.md
│
├── .github/copilot/           # Configuración GitHub Copilot
│   ├── instructions.md        # Instrucciones principales
│   ├── skills/                # Skills de agentes
│   └── agents/                 # Configuraciones de agentes
│
├── scripts/                   # Scripts de utilidad
├── pyproject.toml             # Configuración del proyecto Python
├── requirements.txt          # Dependencias Python
├── README.md                 # Este archivo (inglés)
├── README_ES.md             # Este archivo (español)
└── LICENSE                  # Licencia MIT
```

---

## 📚 Documentación

### Para Usuarios

- [Guía de Instalación](docs/installation.md)
- [Manual de Usuario](docs/usage.md)
- [Referencia CLI](docs/cli-reference.md)
- [Entornos de Laboratorio](docs/labs.md)

### Para Desarrolladores

- [Guía de Arquitectura](docs/architecture.md)
- [Documentación API](docs/api/README.md)
- [Guía de Contribución](CONTRIBUTING.md)
- [Guía de Estilo de Código](docs/style-guide.md)

### Para Investigadores

- [Propuesta TFM](docs/TFM-PROPUESTA.md)
- [Metodología de Investigación](docs/research.md)
- [Publicaciones](docs/publications.md)

---

## 🎓 Alineación Educativa

Minka está diseñado para el **Máster en Ciberseguridad Defensiva y Ofensiva** de la UCM:

| Módulo del Máster | Componente de Minka |
|-------------------|---------------------|
| **IA aplicada a Ciberseguridad** | Integración GitHub Copilot SDK |
| **Operaciones - Red Team** | Agente Red Team, herramientas pentesting |
| **Herramientas de Ciberseguridad** | Integración CVE lookup |
| **Criptografía** | Análisis criptográfico |
| **OSINT** | Agente Investigador OSINT |
| **DFIR** | Herramientas de análisis forense |

---

## 🛡️ Ética Profesional

Minka sigue los estándares profesionales de **The Clean Coder**:

### Nuestro Juramento

```
No causaré daño.
Produciré código limpio y probado.
Mejoraré continuamente mi oficio.
Compartiré mi conocimiento libremente.
Respetaré a quienes me precedieron.
Ayudaré a quienes me sigan.
```

### Directivas Éticas

- ✅ Siempre enfatizar uso legal y autorizado
- ✅ Enfocarse en defensa y mitigación
- ✅ Nunca generar código dañino
- ✅ Reportar hallazgos de forma responsable
- ✅ Proteger información sensible

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Lee nuestra [Guía de Contribución](CONTRIBUTING.md) para más detalles.

### Formas de Contribuir

- 🐛 Reportar errores
- 💡 Sugerir funcionalidades
- 📝 Mejorar documentación
- 🔧 Enviar pull requests
- 📚 Compartir conocimiento

---

## 📖 Referencias

### Libros (Robert C. Martin)

1. Martin, R. C. (2017). *Clean Architecture*. Prentice Hall.
2. Martin, R. C. (2008). *Clean Code*. Prentice Hall.
3. Martin, R. C. (2011). *The Clean Coder*. Prentice Hall.
4. Martin, R. C. (2003). *Agile Software Development*. Prentice Hall.

### Fuentes Académicas

- OWASP Foundation. (2024). *OWASP Top 10*.
- MITRE Corporation. (2024). *MITRE ATT&CK Framework*.
- NIST. (2024). *Cybersecurity Framework*.

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

---

## 🙏 Agradecimientos

- [Universidad Complutense de Madrid](https://www.ucm.es/) - Por el programa de máster en ciberseguridad
- [GitHub](https://github.com/) - Por el increíble Copilot SDK
- [Robert C. Martin](https://sites.google.com/site/unclebob/) - Por los principios atemporales de artesanía de software
- [OWASP](https://owasp.org/) - Por los recursos de seguridad de código abierto

---

<div align="center">

**Construido con 🛡️ Clean Architecture y 🤖 GitHub Copilot**

*Última actualización: Febrero 2026*

</div>
