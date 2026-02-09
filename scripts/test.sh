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

# Run tests directly inside container
docker run --rm -e PYTHONPATH=/app minka-minka-mcp python3 -c "
import asyncio
import sys
sys.path.insert(0, '/app')

from mcp_server.tools.experts import search_experts
from mcp_server.tools.quotes import get_quote
from mcp_server.tools.mitre_attack import get_mitre_technique
from mcp_server.tools.cases import get_case_study
from mcp_server.tools.vulnerabilities import get_cve_info
from mcp_server.tools.ucm_curriculum import get_ucm_module
from mcp_server.tools.narrative import generate_narrative
from mcp_server.tools.clean_architecture import get_clean_arch_info

async def test():
    print('🧪 Testing Minka MCP Server...')
    print('')

    tests_passed = 0
    tests_total = 8

    # Test 1: Experts
    print('1️⃣  Testing Experts Tool...')
    try:
        exp = await search_experts('Carlini')
        if 'Carlini' in exp:
            print('   ✅ Experts: OK')
            tests_passed += 1
        else:
            print('   ❌ Experts: FAILED')
    except Exception as e:
        print(f'   ❌ Experts: ERROR - {e}')

    # Test 2: Quotes
    print('')
    print('2️⃣  Testing Quote Tool...')
    try:
        quote = await get_quote()
        if 'Mitnick' in quote:
            print('   ✅ Quotes: OK')
            tests_passed += 1
        else:
            print('   ❌ Quotes: FAILED')
    except Exception as e:
        print(f'   ❌ Quotes: ERROR - {e}')

    # Test 3: MITRE ATT&CK
    print('')
    print('3️⃣  Testing MITRE ATT&CK Tool...')
    try:
        mitre = await get_mitre_technique('phishing', 'brief')
        if 'T1566' in mitre:
            print('   ✅ MITRE ATT&CK: OK')
            tests_passed += 1
        else:
            print('   ❌ MITRE ATT&CK: FAILED')
    except Exception as e:
        print(f'   ❌ MITRE ATT&CK: ERROR - {e}')

    # Test 4: Case Studies
    print('')
    print('4️⃣  Testing Case Study Tool...')
    try:
        case = await get_case_study('SolarWinds', 'academic', 'summary')
        if 'SolarWinds' in case:
            print('   ✅ Case Studies: OK')
            tests_passed += 1
        else:
            print('   ❌ Case Studies: FAILED')
    except Exception as e:
        print(f'   ❌ Case Studies: ERROR - {e}')

    # Test 5: Vulnerabilities
    print('')
    print('5️⃣  Testing Vulnerability Tool...')
    try:
        vuln = await get_cve_info('Log4Shell')
        if 'Log4Shell' in vuln:
            print('   ✅ Vulnerabilities: OK')
            tests_passed += 1
        else:
            print('   ❌ Vulnerabilities: FAILED')
    except Exception as e:
        print(f'   ❌ Vulnerabilities: ERROR - {e}')

    # Test 6: UCM Curriculum
    print('')
    print('6️⃣  Testing UCM Curriculum Tool...')
    try:
        ucm = await get_ucm_module('Red Team')
        if 'Red Team' in ucm:
            print('   ✅ UCM Curriculum: OK')
            tests_passed += 1
        else:
            print('   ❌ UCM Curriculum: FAILED')
    except Exception as e:
        print(f'   ❌ UCM Curriculum: ERROR - {e}')

    # Test 7: Narrative
    print('')
    print('7️⃣  Testing Narrative Tool...')
    try:
        narrative = await generate_narrative('SQL injection')
        if 'SQL' in narrative:
            print('   ✅ Narrative: OK')
            tests_passed += 1
        else:
            print('   ❌ Narrative: FAILED')
    except Exception as e:
        print(f'   ❌ Narrative: ERROR - {e}')

    # Test 8: Clean Architecture
    print('')
    print('8️⃣  Testing Clean Architecture Tool...')
    try:
        clean = await get_clean_arch_info('SOLID')
        if 'SOLID' in clean:
            print('   ✅ Clean Architecture: OK')
            tests_passed += 1
        else:
            print('   ❌ Clean Architecture: FAILED')
    except Exception as e:
        print(f'   ❌ Clean Architecture: ERROR - {e}')

    print('')
    print(f'✅ Tests completed: {tests_passed}/{tests_total} passed')
    print('')
    print('   To use Minka in Neovim:')
    print('   :MinkaQuote')
    print('   :MinkaExperts Carlini')
    print('   :MinkaCase SolarWinds')

asyncio.run(test())
"

echo ""
echo "🧪 Testing complete!"
