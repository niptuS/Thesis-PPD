#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SH-DATASET — Configurar permisos de captura (ejecutar UNA vez)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "  Configurando permisos de captura de paquetes..."
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "Este script requiere root. Ejecutar con: sudo ./setup_capture.sh"
    exit 1
fi

FIXED=0

# Option 1: Set capabilities on tcpdump
if command -v tcpdump &>/dev/null; then
    TCPDUMP=$(which tcpdump)
    echo "  Configurando tcpdump ($TCPDUMP)..."
    setcap cap_net_raw,cap_net_admin=eip "$TCPDUMP"
    if [ $? -eq 0 ]; then
        echo "  ✓ tcpdump: permisos de captura configurados"
        FIXED=1
    else
        echo "  ✗ tcpdump: error al configurar (filesystem no soporta capabilities?)"
    fi
fi

# Option 2: Set capabilities on dumpcap
if command -v dumpcap &>/dev/null; then
    DUMPCAP=$(which dumpcap)
    echo "  Configurando dumpcap ($DUMPCAP)..."
    setcap cap_net_raw,cap_net_admin=eip "$DUMPCAP"
    if [ $? -eq 0 ]; then
        echo "  ✓ dumpcap: permisos de captura configurados"
        FIXED=1
    fi
fi

# Option 3: Set capabilities on tshark
if command -v tshark &>/dev/null; then
    TSHARK=$(which tshark)
    echo "  Configurando tshark ($TSHARK)..."
    setcap cap_net_raw,cap_net_admin=eip "$TSHARK"
    if [ $? -eq 0 ]; then
        echo "  ✓ tshark: permisos de captura configurados"
        FIXED=1
    fi
fi

# Option 4: Add user to wireshark group
if getent group wireshark &>/dev/null; then
    REAL_USER=${SUDO_USER:-$USER}
    usermod -aG wireshark "$REAL_USER"
    echo "  ✓ Usuario $REAL_USER agregado al grupo wireshark"
    FIXED=1
fi

echo ""
if [ $FIXED -eq 1 ]; then
    echo "  ═══════════════════════════════════════════════"
    echo "  ✓ Configuración completada."
    echo "    Ahora puede ejecutar ./run.sh SIN sudo."
    echo "    (cerrar sesión y volver a entrar si agregó grupo wireshark)"
    echo "  ═══════════════════════════════════════════════"
else
    echo "  ✗ No se encontró tcpdump, dumpcap ni tshark."
    echo "    Instalar: sudo apt install tcpdump"
fi
echo ""
