#!/bin/bash
#
# Minka MCP Server - Start Script
#
# Usage: ./scripts/start.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "🚀 Starting Minka MCP Server..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running."
    echo "   Please start Docker and try again."
    exit 1
fi

# Check if docker-compose.yml exists
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Error: docker-compose.yml not found."
    exit 1
fi

# Remove old container if exists
docker rm -f minka-mcp-server 2>/dev/null || true

# Build and start fresh
docker-compose build --no-cache

# Start container (will exit after tests complete since MCP uses stdio)
docker-compose up -d

echo ""
echo "✅ Minka MCP Server is ready!"
echo ""
echo "   Usage:"
echo "   - Test tools: ./scripts/test.sh"
echo "   - Run quote: docker run --rm -e PYTHONPATH=/app minka-minka-mcp python3 -c \"from mcp_server.tools.quotes import get_quote; import asyncio; print(asyncio.run(get_quote()))\""
echo ""
echo "   Note: MCP server uses stdio transport for GitHub Copilot."
echo "   The container runs once per request and exits."
