#!/bin/bash
# Minka Setup Script
# Script de inicialización para el proyecto Minka

set -e

echo "🔧 Configurando Minka - Asistente de Ciberseguridad"
echo "======================================================"
echo ""

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker no está instalado${NC}"
    echo "Por favor instala Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

echo -e "${GREEN}✓ Docker instalado${NC}"

# Verificar Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose no está instalado${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker Compose instalado${NC}"

# Crear archivo .env si no existe
if [ ! -f "docker/.env" ]; then
    echo -e "${YELLOW}⚠ Archivo .env no encontrado${NC}"
    echo "Creando docker/.env desde plantilla..."
    cp docker/.env.example docker/.env
    echo -e "${YELLOW}⚠ IMPORTANTE: Edita docker/.env y añade tu GITHUB_TOKEN${NC}"
fi

# Crear directorios necesarios
echo "Creando directorios de datos..."
mkdir -p data/{cve_cache,wordlists,payloads,reports}
mkdir -p logs
chmod 755 data logs

# Descargar wordlists básicas
echo "Descargando recursos de seguridad..."
if [ ! -f "data/wordlists/common.txt" ]; then
    echo "Descargando wordlist común..."
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        -o data/wordlists/common.txt 2>/dev/null || echo "Wordlist manual requerida"
fi

echo ""
echo -e "${GREEN}✓ Configuración completada${NC}"
echo ""
echo "Próximos pasos:"
echo "  1. Edita docker/.env y configura tu GITHUB_TOKEN"
echo "  2. Ejecuta: docker-compose -f docker/docker-compose.yml up -d"
echo "  3. Entra al contenedor: docker-compose -f docker/docker-compose.yml exec minka bash"
echo "  4. Inicia Minka: minka start"
echo ""
echo "Para iniciar laboratorios:"
echo "  docker-compose -f docker/docker-compose.yml --profile labs up -d"
