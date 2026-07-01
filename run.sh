#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SH-DATASET — Ejecucion nativa (Linux/Mac)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  SH-DATASET Orchestrator"
echo "  ======================="
echo ""

PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
    echo "[ERROR] Python3 no encontrado"
    exit 1
fi

echo "Verificando dependencias..."
$PYTHON -m pip install -r requirements.txt --quiet 2>/dev/null || \
    $PYTHON -m pip install -r requirements.txt --quiet --break-system-packages 2>/dev/null

stty -ixon 2>/dev/null
export TERM=xterm-256color

mkdir -p outputs/pcap outputs/flows outputs/metadata outputs/logs saves/scenarios plugins/attacks

# Cache sudo credentials BEFORE starting TUI
# This way sudo -n works inside subprocess without prompting
if [ "$(id -u)" -ne 0 ]; then
    echo ""
    echo "  La captura de paquetes requiere sudo."
    echo "  Ingrese su password ahora para cachear credenciales:"
    echo ""
    sudo -v
    if [ $? -ne 0 ]; then
        echo "[WARN] sudo falló. La captura podria no funcionar."
    else
        echo "[OK] Credenciales sudo cacheadas."
        # keep sudo alive in background
        (while true; do sudo -n true; sleep 50; done) &
        SUDO_KEEPALIVE_PID=$!
    fi
    echo ""
fi

$PYTHON App.py "$@"

# cleanup
stty ixon 2>/dev/null
[ -n "$SUDO_KEEPALIVE_PID" ] && kill $SUDO_KEEPALIVE_PID 2>/dev/null
