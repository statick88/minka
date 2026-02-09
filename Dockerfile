FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir mcp

COPY mcp-server/ ./mcp-server/
COPY src/core/personality/ ./src/core/personality/

EXPOSE 3000

CMD ["python", "-m", "mcp-server.server", "--port", "3000"]
