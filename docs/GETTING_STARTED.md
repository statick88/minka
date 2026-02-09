# Minka - Getting Started Guide

## What is Minka?

Minka is a cybersecurity AI assistant powered by GitHub Copilot SDK with MCP (Model Context Protocol) integration. It combines:

- **Expert knowledge** in cybersecurity, AI security, and software architecture
- **Storytelling** inspired by Kevin Mitnick's narrative style
- **Educational approach** from the UCM Master curriculum
- **Clean Architecture** principles from Uncle Bob

## Prerequisites

- **Docker** 20.10+
- **Docker Compose** 2.0+
- **Git** for cloning

That's it! No Python, no pip, no virtual environments needed.

---

## Quick Start (Docker-First)

### 1. Clone and Enter

```bash
git clone https://github.com/statick88/minka.git
cd minka
```

### 2. Start MCP Server

```bash
# Option A: Using the convenience script
./scripts/start.sh

# Option B: Using docker-compose directly
docker-compose up -d
```

### 3. Verify

```bash
# Check logs
docker logs minka-mcp-server

# Should see:
# INFO:     Application startup complete
# Minka MCP Server running on port 3000
```

### 4. Test

```bash
# Run the test script
./scripts/test.sh

# Or manually:
docker exec -it minka-mcp-server python -c "
import asyncio
from tools.experts import search_experts
result = asyncio.run(search_experts('Carlini'))
print(result[:200])
"
```

Expected output:
```
**👤 Nicholas Carlini**
Research Scientist Anthropic | 60K+ citations
📍 Anthropic, Google Brain
🏷️ Adversarial Machine Learning, Security, Neural Networks
```

---

## Usage Examples

### Docker Commands

```bash
# Start the server
docker-compose up -d

# Stop the server
docker-compose down

# View logs
docker-compose logs -f

# Restart
docker-compose restart minka-mcp
```

### Using MCP Tools

```bash
# Search for an expert
docker exec -it minka-mcp-server python -c "
import asyncio
from tools.experts import search_experts
asyncio.run(search_experts('Dawn Song'))
"

# Get a vulnerability
docker exec -it minka-mcp-server python -c "
import asyncio
from tools.vulnerabilities import get_cve_info
asyncio.run(get_cve_info('Log4Shell'))
"

# Get MITRE ATT&CK technique
docker exec -it minka-mcp-server python -c "
import asyncio
from tools.mitre_attack import get_mitre_technique
asyncio.run(get_mitre_technique('ransomware', 'brief'))
"

# Generate a narrative
docker exec -it minka-mcp-server python -c "
import asyncio
from tools.narrative import generate_narrative
asyncio.run(generate_narrative('SQL injection'))
"
```

---

## Neovim Integration

### Prerequisites

- Neovim 0.9+
- Docker running
- MCP server running (`docker-compose up -d`)

### Setup

1. **Copy the plugin configuration**:
```bash
cp ~/.config/nvim/lua/minka.lua ~/.config/nvim/lua/
cp ~/.config/nvim/lua/plugins/minka.lua ~/.config/nvim/lua/plugins/
```

2. **Restart Neovim** or reload:
```vim
:Lazy
:source ~/.config/nvim/init.lua
```

3. **Verify**:
```
:MinkaQuote
```

Should display a Mitnick-style quote in a floating window.

### Commands

| Command | Description |
|---------|-------------|
| `:MinkaQuote` | Get a cybersecurity quote |
| `:MinkaExperts <query>` | Search for a researcher |
| `:MinkaCase <case>` | Get a case study |
| `:MinkaNarrative <concept>` | Generate a narrative |
| `:MinkaVuln <cve>` | Search vulnerability |
| `:MinkaUCM <module>` | UCM curriculum module |
| `:MinkaAISecurity <query>` | AI security research |
| `:MinkaCleanArch <topic>` | Clean Architecture principles |
| `:MinkaMitre <technique>` | MITRE ATT&CK technique |

### Keybindings

| Keybinding | Description |
|------------|-------------|
| `<leader>mq` | Get quote |
| `<leader>me` | Search expert |
| `<leader>mc` | Get case study |
| `<leader>mn` | Generate narrative |
| `<leader>mv` | Search vulnerability |
| `<leader>mu` | UCM module |
| `<leader>ma` | AI security paper |
| `<leader>ml` | Clean architecture |

---

## GitHub Codespaces

### 1. Open in Codespaces

1. Go to https://github.com/statick88/minka
2. Click **"Code"** → **"Codespaces"**
3. Click **"Create codespace on main"**

### 2. Automatic Setup

The `.devcontainer/devcontainer.json` will:
- Install Docker-in-Docker
- Build the MCP server container
- Expose port 3000

### 3. Start Using

```bash
# In the Codespaces terminal
docker-compose up -d

# Open Neovim
nvim

# Use Minka commands
:MinkaQuote
:MinkaMitre "phishing"
```

---

## Architecture

```
Minka/
├── .github/copilot/
│   ├── agents/minka.agent.yml    # Custom agent
│   └── mcp.json                   # MCP configuration
├── mcp-server/
│   ├── server.py                  # MCP server (Python)
│   └── tools/                     # 9 MCP tools
│       ├── experts.py             # Researchers database
│       ├── cases.py               # Case studies
│       ├── mitre_attack.py        # MITRE ATT&CK
│       ├── vulnerabilities.py     # CVE database
│       └── ...
├── docs/
│   ├── GETTING_STARTED.md        # This file
│   ├── COMMANDS.md               # Tool reference
│   └── PERSONALITY.md             # Philosophy
├── scripts/
│   ├── start.sh                   # Start server
│   ├── test.sh                    # Test tools
│   └── stop.sh                    # Stop server
├── docker-compose.yml             # Docker orchestration
├── Dockerfile                     # Server container
└── .devcontainer/                 # Codespaces config
```

---

## Troubleshooting

### "Connection refused" on port 3000

```bash
# Check if container is running
docker ps | grep minka

# If not running, start it
docker-compose up -d

# Check logs
docker-compose logs
```

### "Module not found" errors

```bash
# Rebuild the container
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Neovim commands not working

```bash
# Verify minka.lua is loaded
nvim -c "lua require('minka')" -c "q"

# Check for errors
:Messages

# Reload configuration
:Lazy
:source ~/.config/nvim/init.lua
```

### Container uses too much memory

```bash
# Check memory usage
docker stats minka-mcp-server

# Limit memory in docker-compose.yml if needed
```

---

## Next Steps

1. Read [PERSONALITY.md](./PERSONALITY.md) to understand Minka's philosophy
2. Check [COMMANDS.md](./COMMANDS.md) for all available tools
3. Try asking Minka about cybersecurity topics in Neovim

---

## Development (Optional)

If you want to develop Minka natively:

```bash
# Clone repository
git clone https://github.com/statick88/minka.git
cd minka

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python -m mcp-server.server
```

**Note**: This is optional. Docker is the recommended approach for using Minka.
