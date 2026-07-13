#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SH-DATASET — Configure capture permissions (run ONCE)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  Configuring packet capture permissions..."
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "This script requires root. Run with: sudo ./setup_capture.sh"
    exit 1
fi

FIXED=0

# Option 1: Set capabilities on tcpdump
if command -v tcpdump &>/dev/null; then
    TCPDUMP=$(which tcpdump)
    echo "  Configuring tcpdump ($TCPDUMP)..."
    setcap cap_net_raw,cap_net_admin=eip "$TCPDUMP"
    if [ $? -eq 0 ]; then
        echo "  ✓ tcpdump: capture permissions configured"
        FIXED=1
    else
        echo "  ✗ tcpdump: error configuring (filesystem doesn't support capabilities?)"
    fi
fi

# Option 2: Set capabilities on dumpcap
if command -v dumpcap &>/dev/null; then
    DUMPCAP=$(which dumpcap)
    echo "  Configuring dumpcap ($DUMPCAP)..."
    setcap cap_net_raw,cap_net_admin=eip "$DUMPCAP"
    if [ $? -eq 0 ]; then
        echo "  ✓ dumpcap: capture permissions configured"
        FIXED=1
    fi
fi

# Option 3: Set capabilities on tshark
if command -v tshark &>/dev/null; then
    TSHARK=$(which tshark)
    echo "  Configuring tshark ($TSHARK)..."
    setcap cap_net_raw,cap_net_admin=eip "$TSHARK"
    if [ $? -eq 0 ]; then
        echo "  ✓ tshark: capture permissions configured"
        FIXED=1
    fi
fi

# Option 4: Add user to wireshark group
if getent group wireshark &>/dev/null; then
    REAL_USER=${SUDO_USER:-$USER}
    usermod -aG wireshark "$REAL_USER"
    echo "  ✓ User $REAL_USER added to wireshark group"
    FIXED=1
fi

echo ""
if [ $FIXED -eq 1 ]; then
    echo "  ═══════════════════════════════════════════════"
    echo "  ✓ Configuration completed."
    echo "    You can now run ./run.sh WITHOUT sudo."
    echo "    (log out and back in if you added the wireshark group)"
    echo "  ═══════════════════════════════════════════════"
else
    echo "  ✗ Neither tcpdump, dumpcap nor tshark were found."
    echo "    Install: sudo apt install tcpdump"
fi
echo ""
