# Minka como Trabajo Fin de Máster (TFM)

## Resumen Ejecutivo

**Minka** es un proyecto piloto que demuestra la aplicación práctica de **Inteligencia Artificial aplicada a la Ciberseguridad**, específicamente en el ámbito de la investigación de vulnerabilidades y seguridad ofensiva.

### 🎯 Alineación con el Máster UCM

Este proyecto se alinea directamente con el **Módulo 5: IA aplicada a la Ciberseguridad** del máster, abordando específicamente:

- **Introducción a los Copilot/LLM en Ciberseguridad**
- **Fundamentos de la Inteligencia Artificial en Ciberseguridad**
- **Aplicaciones Prácticas de la IA en Ciberseguridad**
- **Herramientas de Asistencia Inteligente (Copilots)**

## 📊 Contribución al Campo

### Problema Identificado

Los estudiantes y profesionales de ciberseguridad enfrentan:
1. Curva de aprendizaje pronunciada en herramientas complejas
2. Dificultad para contextualizar vulnerabilidades
3. Necesidad de práctica segura sin riesgos legales
4. Sobrecarga de información de CVEs y advisories

### Solución Propuesta

Minka integra GitHub Copilot SDK para crear un asistente conversacional que:
- **Explica** conceptos de vulnerabilidades de forma interactiva
- **Genera** PoCs educativos automáticamente
- **Integra** laboratorios vulnerables para práctica inmediata
- **Conecta** teoría y práctica del máster

## 🔬 Metodología

### Fase 1: Investigación (Semanas 1-3) ✅ COMPLETADA
- ✅ Análisis de GitHub Copilot SDK
- ✅ Estudio de vulnerabilidades comunes (OWASP Top 10)
- ✅ Revisión de técnicas MITRE ATT&CK
- ✅ Investigación de Robert C. Martin (Clean Architecture)

### Fase 2: Diseño (Semanas 4-5) ✅ COMPLETADA
- ✅ Arquitectura de microservicios con Docker
- ✅ Diseño de agentes especializados (Red Team, OSINT, Blue Team)
- ✅ Definición de herramientas MCP
- ✅ Configuración de GitHub Copilot Skills

### Fase 3: Implementación (Semanas 6-10) ✅ EN PROGRESO
- ✅ Desarrollo del core con Python (MinkaClient, SessionManager)
- ✅ Integración GitHub Copilot SDK
- ✅ Implementación de CLI interactiva (Click + Rich)
- ✅ Configuración de laboratorios vulnerables (DVWA, Juice Shop, WebGoat)
- 🔄 Implementación de agentes especializados (Red Team, OSINT)
- 🔲 Implementación de Blue Team Agent
- 🔲 Pruebas de integración

### Fase 4: Validación (Semanas 11-13)
- Pruebas con escenarios reales
- Evaluación de usabilidad
- Documentación académica

## 🏗️ Arquitectura de Agentes

### Red Team Agent
Especializado en operaciones de seguridad ofensiva:
- **Investigación de Exploits**: Búsqueda y análisis de CVEs
- **Generación de Payloads**: Creación de payloads de prueba seguros
- **Técnicas de Explotación**: Guía sobre técnicas MITRE ATT&CK
- **Post-Explotación**: Estrategias de movimiento lateral

### OSINT Agent
Especializado en inteligencia de fuentes abiertas:
- **Enumeración de Dominios**: WHOIS, DNS, subdominios
- **Descubrimiento de Emails**: Patrones de email, breach data
- **Fingerprinting Tecnológico**: Identificación de stacks
- **Inteligencia Social**: Perfiles en redes sociales

### Blue Team Agent (En Desarrollo)
Especializado en defensa:
- **Análisis de Vulnerabilidades**: Priorización y scoring
- **Hardening**: Guías de remediación
- **Detección**: Rules YARA, IOC extraction
- **Respuesta a Incidentes**: Playbooks de respuesta

## 📈 Resultados Esperados

### Métricas de Éxito

1. **Funcionales**:
   - ✅ Integración exitosa con GitHub Copilot SDK
   - ✅ CLI interactivo funcional
   - ✅ 3+ agentes especializados
   - ✅ 5+ laboratorios vulnerables operativos
   - ✅ Capacidad de generar PoCs educativos

2. **Académicos**:
   - Documentación de diseño arquitectónico
   - Análisis de seguridad del asistente
   - Comparativa con herramientas existentes
   - Guía de uso para estudiantes del máster

3. **Técnicos**:
   - Cobertura de tests > 70%
   - Contenerización completa
   - Documentación de API

## 🎓 Aprendizajes Clave

### Competencias Desarrolladas

1. **Seguridad Ofensiva**:
   - Análisis de vulnerabilidades
   - Pentesting metodológico
   - Desarrollo de exploits educativos

2. **Inteligencia Artificial**:
   - Integración de LLMs en workflows
   - Diseño de prompts especializados
   - Orquestación de agentes

3. **DevSecOps**:
   - Contenerización segura
   - Automatización de despliegue
   - Gestión de secrets

## 🚀 Futuro del Proyecto

### Roadmap Post-TFM

**Fase 2: Expansión Web** (3 meses)
- Dashboard React para visualización
- Historial de investigaciones
- Editor de PoCs integrado

**Fase 3: Integración Voz** (2 meses)
- Bot de Telegram
- Comandos por voz
- Notificaciones de CVEs

**Fase 4: Comunidad** (Continuo)
- Open source en GitHub
- Contribuciones de la comunidad
- Integración con más laboratorios

## 📚 Bibliografía y Referencias

### Documentación Oficial
1. GitHub. (2026). GitHub Copilot SDK Documentation.
2. Rodriguez, M. (2026). Build an agent into any app with the GitHub Copilot SDK. GitHub Blog.
3. Anthropic. (2024). Claude API Documentation.
4. OpenAI. (2024). GPT-4 Technical Report.

### Marco Teórico
5. Song, F., et al. (2024). The Impact of Generative AI on Collaborative Open-Source Software Development. arXiv:2410.02091.
6. OWASP Foundation. (2024). OWASP Top 10:2021.
7. MITRE Corporation. (2024). MITRE ATT&CK Framework.

### Herramientas y Laboratorios
8. OWASP. (2024). Juice Shop Project.
9. DVWA. (2024). Damn Vulnerable Web Application.
10. PortSwigger. (2024). Web Security Academy.

## 🏆 Conclusión

Minka representa una **innovación educativa** que combina:
- **Vanguardia tecnológica**: GitHub Copilot SDK
- **Práctica segura**: Laboratorios contenerizados
- **Aplicación académica**: Módulos del máster UCM

Este proyecto no solo cumple los requisitos del TFM sino que proporciona una **herramienta reusable** para futuros estudiantes del máster y la comunidad de ciberseguridad.

### Impacto Esperado

- **Educativo**: Facilitar el aprendizaje de vulnerabilidades
- **Profesional**: Automatizar tareas de investigación
- **Comunitario**: Contribuir al open source de ciberseguridad

---

**Autor**: Estudiante del Máster en Ciberseguridad Defensiva y Ofensiva  
**Universidad**: Universidad Complutense de Madrid (UCM)  
**Edición**: 2ª - Febrero 2026  
**Director de TFM**: [Por determinar]
