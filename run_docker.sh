#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SH-DATASET — Ejecucion Docker (portabilidad/reproducibilidad)
# Requiere: Docker + Docker Compose
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  SH-DATASET Docker"
echo "  =================="
echo ""

# Check Docker
if ! command -v docker &>/dev/null; then
    echo "[ERROR] Docker no encontrado. Instalar: https://docs.docker.com/get-docker/"
    exit 1
fi

# Detect OS for network note
if [[ "$(uname)" == "Linux" ]]; then
    echo "  Modo: Linux — --net=host expone interfaces reales del host"
else
    echo "  NOTA: En Docker Desktop (Mac) las interfaces mostradas"
    echo "        son de la VM interna. Para captura real, usar: ./run.sh"
fi
echo ""

echo "Construyendo imagen..."
docker compose build --quiet 2>/dev/null || docker-compose build --quiet 2>/dev/null

echo "Iniciando contenedor interactivo..."
echo ""
docker compose run --rm sh-dataset 2>/dev/null || docker-compose run --rm sh-dataset 2>/dev/null
