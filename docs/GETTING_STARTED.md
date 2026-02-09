# Minka - Getting Started Guide

## What is Minka?

Minka is a cybersecurity AI assistant powered by GitHub Copilot SDK with MCP (Model Context Protocol) integration. It combines:

- **Expert knowledge** in cybersecurity, AI security, and software architecture
- **Storytelling** inspired by Kevin Mitnick's narrative style
- **Educational approach** from the UCM Master curriculum
- **Clean Architecture** principles from Uncle Bob

## Prerequisites

- Python 3.11+
- GitHub Copilot subscription
- Neovim 0.9+ or VS Code with Copilot extension

## Quick Start

### 1. Clone and Install

```bash
cd /Users/statick/Minka
source venv/bin/activate
pip install -r requirements.txt
pip install mcp
```

### 2. Start MCP Server

```bash
python -m mcp-server.server
```

### 3. Configure Your Editor

#### Neovim
```lua
-- ~/.config/nvim/lua/minka.lua
require('minka').setup({
  server = 'localhost:3000',
  auto_attach = true,
})
```

#### VS Code
The `mcp.json` is automatically loaded by GitHub Copilot.

## Usage Examples

### Search for an Expert
```
User: "¿Quién es Nicholas Carlini?"
Minka: **👤 Nicholas Carlini**
Research Scientist Anthropic | 60K+ citations
📍 Anthropic, Google Brain
🏷️ Adversarial Machine Learning, Security, Neural Networks
```

### Get a Vulnerability
```
User: "Cuéntame sobre Log4Shell"
Minka: ## Log4Shell (CVE-2021-44228)

> 🎭 *¿Sabes qué hace esto tan fascinante?*

**Log4Shell** es una vulnerabilidad crítica en Apache Log4j...

### La Historia
En diciembre de 2021, investigadores descubrieron...

### La Técnica
JNDI lookup permite ejecución remota de código...

### Prevención
- Actualizar a Log4j 2.17+
- Limitar conexiones JNDI
- WAF rules
```

### Learn Clean Architecture
```
User: "Explicame SOLID"
Minka: ## SOLID Principles

Los cinco principios del diseño orientado a objetos:

1. **S**ingle Responsibility Principle
2. **O**pen/Closed Principle
3. **L**iskov Substitution Principle
4. **I**nterface Segregation Principle
5. **D**ependency Inversion Principle
```

## Commands Reference

See [COMMANDS.md](./COMMANDS.md) for complete tool reference.

## Architecture

```
Minka/
├── .github/copilot/
│   ├── agents/minka.agent.yml    # Custom agent
│   └── mcp.json                   # MCP configuration
├── mcp-server/
│   ├── server.py                  # MCP server
│   └── tools/                     # 9 MCP tools
├── src/core/personality/
│   ├── SOUL.md                    # 6 profiles
│   └── IDENTITY.md                # Storytelling style
└── docs/
    ├── GETTING_STARTED.md         # This file
    ├── COMMANDS.md                # Tool reference
    └── PERSONALITY.md             # Philosophy
```

## Next Steps

1. Read [PERSONALITY.md](./PERSONALITY.md) to understand Minka's philosophy
2. Check [COMMANDS.md](./COMMANDS.md) for all available tools
3. Try asking Minka about your cybersecurity questions

## Troubleshooting

**Server won't start?**
```bash
# Check Python environment
source venv/bin/activate
python -c "import mcp; print('OK')"
```

**Tools not available?**
```bash
# Verify mcp.json is in correct location
ls -la .github/copilot/
```

**Neovim not connecting?**
```bash
# Test MCP server manually
python -c "
import asyncio
import sys
sys.path.insert(0, 'mcp-server')
from tools.experts import search_experts
asyncio.run(search_experts('Carlini'))
"
```
