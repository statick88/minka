#!/bin/bash
#
# Minka MCP Server - Test Script
#
# Usage: ./scripts/test.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "🧪 Testing Minka MCP Server..."
echo ""

# Check if container is running
if ! docker ps | grep -q "minka-mcp-server"; then
    echo "❌ Error: Minka MCP Server is not running."
    echo "   Start it first with: ./scripts/start.sh"
    exit 1
fi

# Run tests
echo "1️⃣  Testing Experts Tool..."
EXPERT=$(docker exec -it minka-mcp-server python -c "
import asyncio
from tools.experts import search_experts
asyncio.run(search_experts('Carlini'))
" 2>/dev/null)

if echo "$EXPERT" | grep -q "Nicholas Carlini"; then
    echo "   ✅ Experts: OK"
else
    echo "   ❌ Experts: FAILED"
fi

echo ""
echo "2️⃣  Testing Quote Tool..."
QUOTE=$(docker exec -it minka-mcp-server python -c "
import asyncio
from tools.quotes import get_quote
asyncio.run(get_quote())
" 2>/dev/null)

if echo "$QUOTE" | grep -q "Mitnick"; then
    echo "   ✅ Quotes: OK"
else
    echo "   ❌ Quotes: FAILED"
fi

echo ""
echo "3️⃣  Testing MITRE ATT&CK Tool..."
MITRE=$(docker exec -it minka-mcp-server python -c "
import asyncio
from tools.mitre_attack import get_mitre_technique
asyncio.run(get_mitre_technique('phishing', 'brief'))
" 2>/dev/null)

if echo "$MITRE" | grep -q "T1566"; then
    echo "   ✅ MITRE ATT&CK: OK"
else
    echo "   ❌ MITRE ATT&CK: FAILED"
fi

echo ""
echo "4️⃣  Testing Case Study Tool..."
CASE=$(docker exec -it minka-mcp-server python -c "
import asyncio
from tools.cases import get_case_study
asyncio.run(get_case_study('SolarWinds', 'modern', 'summary'))
" 2>/dev/null)

if echo "$CASE" | grep -q "SolarWinds"; then
    echo "   ✅ Case Studies: OK"
else
    echo "   ❌ Case Studies: FAILED"
fi

echo ""
echo "5️⃣  Testing Vulnerability Tool..."
VULN=$(docker exec -it minka-mcp-server python -c "
import asyncio
from tools.vulnerabilities import get_cve_info
asyncio.run(get_cve_info('Log4Shell'))
" 2>/dev/null)

if echo "$VULN" | grep -q "Log4Shell"; then
    echo "   ✅ Vulnerabilities: OK"
else
    echo "   ❌ Vulnerabilities: FAILED"
fi

echo ""
echo "6️⃣  Testing UCM Curriculum Tool..."
UCM=$(docker exec -it minka-mcp-server python -c "
import asyncio
from tools.ucm_curriculum import get_ucm_module
asyncio.run(get_ucm_module('Red Team'))
" 2>/dev/null)

if echo "$UCM" | grep -q "Red Team"; then
    echo "   ✅ UCM Curriculum: OK"
else
    echo "   ❌ UCM Curriculum: FAILED"
fi

echo ""
echo "7️⃣  Testing Narrative Tool..."
NARRATIVE=$(docker exec -it minka-mcp-server python -c "
import asyncio
from tools.narrative import generate_narrative
asyncio.run(generate_narrative('SQL injection'))
" 2>/dev/null)

if echo "$NARRATIVE" | grep -q "SQL"; then
    echo "   ✅ Narrative: OK"
else
    echo "   ❌ Narrative: FAILED"
fi

echo ""
echo "8️⃣  Testing Clean Architecture Tool..."
CLEAN=$(docker exec -it minka-mcp-server python -c "
import asyncio
from tools.clean_architecture import get_clean_arch_info
asyncio.run(get_clean_arch_info('SOLID'))
" 2>/dev/null)

if echo "$CLEAN" | grep -q "SOLID"; then
    echo "   ✅ Clean Architecture: OK"
else
    echo "   ❌ Clean Architecture: FAILED"
fi

echo ""
echo "✅ All tests completed!"
echo ""
echo "   To use Minka in Neovim:"
echo "   :MinkaQuote"
echo "   :MinkaExperts Carlini"
echo "   :MinkaCase SolarWinds"
