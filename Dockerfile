# ═══════════════════════════════════════════════════════════════
# SH-DATASET Orchestrator — Docker (Portable Kali Toolkit)
#
# Pinned base image and APT package versions for reproducibility.
# To upgrade: bump KALI_BASE_TAG and the package versions together,
# then re-run the test suite to confirm nothing broke.
# ═══════════════════════════════════════════════════════════════

# Pinned Kali rolling snapshot — bump explicitly when upgrading.
# Find available tags at: https://hub.docker.com/r/kalilinux/kali-rolling/tags
ARG KALI_BASE_TAG=2025.2
FROM kalilinux/kali-rolling:${KALI_BASE_TAG}

ENV DEBIAN_FRONTEND=noninteractive

# ── Locale UTF-8 (required for TUI box-drawing characters) ──
RUN apt-get update && apt-get install -y --no-install-recommends \
        locales=2.* \
    && sed -i 's/# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen \
    && locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8
ENV TERM=xterm-256color
ENV NCURSES_NO_UTF8_ACS=1

# ── System: Kali attack tools + capture (versions pinned by Kali repo) ──
# The exact APT versions come from the Kali ${KALI_BASE_TAG} snapshot,
# so they are reproducible as long as the base image tag is pinned.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3=3.13.* \
        python3-pip \
        python3-venv \
        nmap=7.94+* \
        hping3=3.* \
        hydra=9.* \
        dsniff=2.4b1+* \
        ettercap-text-only=1:0.8.* \
        mosquitto-clients=2.* \
        aircrack-ng=1:1.7.* \
        libcoap3-bin=4.3.* \
        tcpdump=4.99.* \
        tshark=4.* \
        wireshark-common=4.* \
        iputils-ping=3:* \
        net-tools=2.* \
        iproute2=6.* \
        arp-scan=1.* \
        openssh-client=1:9.* \
        sshpass=1.* \
        curl=8.* \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies (pinned in requirements/base.txt) ──
WORKDIR /app
COPY requirements/ ./requirements/
RUN pip install --no-cache-dir --break-system-packages -r requirements/base.txt

# ── Application ──
COPY . /app
RUN mkdir -p /app/outputs/pcap /app/outputs/metadata \
    /app/outputs/flows /app/outputs/logs \
    /app/saves/scenarios /app/plugins/attacks

ENTRYPOINT ["python3", "App.py"]
