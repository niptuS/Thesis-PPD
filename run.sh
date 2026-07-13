#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SH-DATASET — Native execution (Linux/Mac)
#
# First time: run  sudo ./setup_capture.sh
# Then:        run  ./run.sh
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  SH-DATASET Orchestrator"
echo "  ======================="
echo ""

PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
    echo "[ERROR] Python3 not found"
    exit 1
fi

echo "Checking dependencies..."
$PYTHON -m pip install -r requirements.txt --quiet 2>/dev/null || \
    $PYTHON -m pip install -r requirements.txt --quiet --break-system-packages 2>/dev/null

stty -ixon 2>/dev/null
export TERM=xterm-256color

mkdir -p outputs/pcap outputs/flows outputs/metadata outputs/logs saves/scenarios plugins/attacks

# Check if capture tools have proper permissions
CAN_CAPTURE=0
for tool in tcpdump dumpcap tshark; do
    if command -v $tool &>/dev/null; then
        # Test if we can capture without root
        timeout 1 $tool -D &>/dev/null 2>&1
        if [ $? -eq 0 ]; then
            CAN_CAPTURE=1
            break
        fi
    fi
done

if [ $CAN_CAPTURE -eq 0 ] && [ "$EUID" -ne 0 ]; then
    echo ""
    echo "  [WARN] No capture permissions."
    echo "         Run first: sudo ./setup_capture.sh"
    echo "         Or run as root: sudo ./run.sh"
    echo ""
    read -p "  Continue without capture? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
$PYTHON App.py "$@"
stty ixon 2>/dev/null
