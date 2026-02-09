FROM python:3.11-slim

LABEL maintainer="statick88@github.com"
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
COPY src/core/personality/ ./src/core/personality/

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash minka && \
    chown -R minka:minka /app
USER minka

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Expose port
EXPOSE 3000

# Run server (redirect output to /dev/null for health check)
CMD ["python", "-m", "mcp_server.server"]
