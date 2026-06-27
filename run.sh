#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SH-DATASET — Ejecucion nativa (Linux/Mac)
# Requiere: Python 3.10+, tcpdump o tshark
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  SH-DATASET Orchestrator"
echo "  ======================="
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python3 no encontrado. Instalar: sudo apt install python3"
    exit 1
fi

# Install dependencies
echo "Verificando dependencias..."
pip3 install -r requirements.txt --quiet 2>/dev/null || \
    pip3 install -r requirements.txt --quiet --break-system-packages 2>/dev/null

# Check capture tools
if ! command -v tcpdump &>/dev/null && ! command -v tshark &>/dev/null; then
    echo "[WARN] tcpdump ni tshark encontrados."
    echo "       Instalar: sudo apt install tcpdump"
    echo ""
fi

echo "Iniciando SH-DATASET..."
echo ""
python3 App.py
