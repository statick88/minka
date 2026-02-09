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

# Start the MCP server
docker-compose up -d

# Wait for the server to be ready
echo "⏳ Waiting for MCP server to start..."
sleep 3

# Check if container is running
if docker ps | grep -q "minka-mcp-server"; then
    echo "✅ Minka MCP Server is running!"
    echo ""
    echo "   Server URL: http://localhost:3000"
    echo "   Logs: docker-compose logs -f"
    echo "   Stop: ./scripts/stop.sh"
    echo "   Test: ./scripts/test.sh"
else
    echo "❌ Error: Failed to start MCP server."
    echo "   Check logs with: docker-compose logs"
    exit 1
fi
