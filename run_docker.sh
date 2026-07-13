#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SH-DATASET — Docker execution (portability/reproducibility)
# Requires: Docker + Docker Compose
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  SH-DATASET Docker"
echo "  =================="
echo ""

# Check Docker
if ! command -v docker &>/dev/null; then
    echo "[ERROR] Docker not found. Install: https://docs.docker.com/get-docker/"
    exit 1
fi

# Detect OS for network note
if [[ "$(uname)" == "Linux" ]]; then
    echo "  Mode: Linux — --net=host exposes real host interfaces"
else
    echo "  NOTE: On Docker Desktop (Mac) the displayed interfaces"
    echo "        belong to the internal VM. For real capture, use: ./run.sh"
fi
echo ""

echo "Building image..."
docker compose build --quiet 2>/dev/null || docker-compose build --quiet 2>/dev/null

echo "Starting interactive container..."
echo ""
docker compose run --rm sh-dataset 2>/dev/null || docker-compose run --rm sh-dataset 2>/dev/null
