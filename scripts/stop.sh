#!/bin/bash
#
# Minka MCP Server - Stop Script
#
# Usage: ./scripts/stop.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "🛑 Stopping Minka MCP Server..."

# Stop the MCP server
docker-compose down

echo "✅ Minka MCP Server stopped."
echo ""
echo "   To start again: ./scripts/start.sh"
