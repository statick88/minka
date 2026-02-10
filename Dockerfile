FROM python:3.11-slim

LABEL maintainer="statick88@github"
LABEL description="Minka MCP Server - Cybersecurity AI Assistant"
LABEL version="1.0.0"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install MCP
RUN pip install --no-cache-dir mcp>=1.26.0

# Copy application
COPY mcp_server/ ./mcp_server/

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash minka && \
    chown -R minka:minka /app
USER minka

# Run server (stdio transport for MCP)
CMD ["python", "-m", "mcp_server.server"]
