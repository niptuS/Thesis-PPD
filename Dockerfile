# ═══════════════════════════════════════════════════════════════
# SH-DATASET Orchestrator — Docker (Portable Kali Toolkit)
# ═══════════════════════════════════════════════════════════════
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# ── Locale UTF-8 (required for TUI box-drawing characters) ──
RUN apt-get update && apt-get install -y --no-install-recommends locales \
    && sed -i 's/# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen \
    && locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8
ENV TERM=xterm-256color
ENV NCURSES_NO_UTF8_ACS=1

# ── System: Kali attack tools + capture ──
RUN apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    nmap hping3 hydra dsniff ettercap-text-only \
    mosquitto-clients aircrack-ng libcoap3-bin \
    tcpdump tshark wireshark-common \
    iputils-ping net-tools iproute2 arp-scan \
    openssh-client sshpass curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ──
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# ── Application ──
COPY . /app
RUN mkdir -p /app/outputs/pcap /app/outputs/metadata \
    /app/outputs/flows /app/outputs/logs \
    /app/saves/scenarios /app/plugins/attacks

ENTRYPOINT ["python3", "App.py"]
