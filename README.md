# Minka - Cybersecurity AI Assistant

Minka es un asistente de IA para ciberseguridad potenciado por GitHub Copilot SDK con integración MCP (Model Context Protocol).

## Características

- 🎭 **Estilo Mitnick** - Narrativas de hacking con técnica de storytelling
- 🔬 **Investigadores** - Base de datos de expertos en seguridad (Carlini, Song, Oprea...)
- 📚 **Casos de Estudio** - Stuxnet, SolarWinds, Log4Shell, WannaCry...
- 🎯 **MITRE ATT&CK** - Técnicas, tácticas y grupos APT
- 🐞 **CVEs** - Base de datos de vulnerabilidades (50+)
- 🎓 **UCM Curriculum** - Master en Ciberseguridad UCM
- 🏗️ **Clean Architecture** - Principios SOLID, Uncle Bob

## Inicio Rápido (Docker)

```bash
# Clonar
git clone https://github.com/statick88/minka.git
cd minka

# Iniciar servidor
./scripts/start.sh

# Verificar
./scripts/test.sh
```

## Uso

### Docker Commands

```bash
# Iniciar
docker-compose up -d

# Ver logs
docker-compose logs -f

# Detener
docker-compose down
```

### Herramientas MCP

```bash
# Buscar investigador
docker exec -it minka-mcp-server python -c "
import asyncio
from tools.experts import search_experts
asyncio.run(search_experts('Carlini'))
"

# Obtener CVE
docker exec -it minka-mcp-server python -c "
import asyncio
from tools.vulnerabilities import get_cve_info
asyncio.run(get_cve_info('Log4Shell'))
"

# Técnica MITRE ATT&CK
docker exec -it minka-mcp-server python -c "
import asyncio
from tools.mitre_attack import get_mitre_technique
asyncio.run(get_mitre_technique('ransomware', 'brief'))
"
```

## Neovim Integration

```vim
" Comandos
:MinkaQuote
:MinkaExperts "Dawn Song"
:MinkaCase "SolarWinds"
:MinkaNarrative "SQL injection"
:MinkaVuln "Heartbleed"
:MinkaUCM "Red Team"
:MinkaMitre "phishing"
:MinkaCleanArch "SOLID"

" Keybindings
<leader>mq  " Cita
<leader>me  " Experto
<leader>mc  " Caso
<leader>mn  " Narrativa
<leader>mv  " Vulnerabilidad
<leader>mu  " UCM
<leader>ml  " Clean Architecture
```

## Documentación

- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) - Guía de inicio
- [docs/COMMANDS.md](docs/COMMANDS.md) - Referencia de comandos
- [docs/PERSONALITY.md](docs/PERSONALITY.md) - Filosofía Minka

## Desarrollo

```bash
# Desarrollo con hot-reload
docker-compose -f docker-compose.yml up -d minka-mcp-dev

# Compilar imagen
docker-compose build

# Tests
./scripts/test.sh
```

## GitHub Codespaces

1. Abrir https://github.com/statick88/minka
2. Codespaces → Create codespace
3. docker-compose up -d
4. nvim :MinkaQuote

## Licencia

MIT
