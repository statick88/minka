#!/bin/bash
# Start Minka

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🚀 Iniciando Minka..."

# Verificar que existe .env
if [ ! -f "${PROJECT_ROOT}/docker/.env" ]; then
    echo "❌ Error: No se encontró docker/.env"
    echo "Ejecuta primero: ${PROJECT_ROOT}/scripts/setup.sh"
    exit 1
fi

# Verificar que GITHUB_TOKEN está configurado
if ! grep -q "GITHUB_TOKEN=ghp_" "${PROJECT_ROOT}/docker/.env"; then
    echo "⚠️  Advertencia: GITHUB_TOKEN no configurado en docker/.env"
    echo "Edita el archivo y añade tu token antes de continuar."
    exit 1
fi

# Iniciar servicios
cd "${PROJECT_ROOT}/docker"
docker-compose up -d

# Esperar a que estén listos
echo "⏳ Esperando a que los servicios estén listos..."
sleep 5

# Verificar estado
if docker-compose ps | grep -q "minka.*Up"; then
    echo "✅ Minka está corriendo"
    echo ""
    echo "Para entrar al contenedor:"
    echo "  docker-compose exec minka bash"
    echo ""
    echo "Para ver logs:"
    echo "  docker-compose logs -f minka"
else
    echo "❌ Error al iniciar Minka"
    echo "Revisa los logs: docker-compose logs"
    exit 1
fi
