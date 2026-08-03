# SH-DATASET

Software for creating datasets to evaluate intrusion detection systems in Smart Home IoT networks.

TUI (Terminal User Interface) orchestrator that coordinates benign traffic and real attacks on IoT devices in a local network, capturing the resulting traffic in PCAP format and generating labeled CSV datasets ready to train or evaluate an IDS.

Developed as a thesis project for the Universidad de Santiago de Chile (USACH).

## Description

SH-DATASET lets you design experimental scenarios that combine benign actions (HTTP/MQTT requests to real IoT devices) with network attacks (executed from Kali Linux and Python scripts), simultaneously capturing all network traffic. The result is a dataset with network flows labeled as `attack`, `benign` or `unknown`, useful for training and evaluating intrusion detection models.

### Workflow

```
1. Scan network    → discover IoT devices on the LAN
2. Classify        → assign roles (target, attacker) and types (camera, bulb, sensor...)
3. Create profiles → scan HTTP/MQTT endpoints available on each device
4. Design timeline → schedule benign events and attacks with temporal offsets
5. Execute         → PCAP capture + coordinated event execution
6. Export          → CSV with labeled flows + metadata JSON + execution log
```

## Architecture

```
App.py                          ← Entry point
design/
  Menu.py                       ← Main TUI (curses)
  Menu_*.py                     ← Menu sections (devices, timeline, attacks, etc.)
  handlers/                     ← Section controllers
  overlays.py                   ← Interactive modals (selectors, inputs)
  models.py                     ← UI dataclasses
modules/
  devices/                      ← Network scanning (nmap, ARP, scapy)
  attacks/                      ← 17-attack library + plugin system
  profiles/                     ← Benign profiles + endpoint scanner (103+ HTTP + MQTT)
  timeline/                     ← datetime-aware event manager
  comms/                        ← Unified communication layer (Local, HTTP, MQTT, SSH)
  services/                     ← Extracted services (single responsibility):
    capture_service.py          ←   CaptureService           — PCAP capture
    event_executor.py           ←   EventExecutor            — fires benign & attack events
    flow_extractor.py           ←   FlowExtractor            — PCAP → raw flow rows
    flow_labeler.py             ←   FlowLabeler              — flow labeling (scientific decision)
    artifact_manifest_writer.py ←   ArtifactManifestWriter   — metadata JSON + execution log
  live_executions/              ← Thin orchestrator wiring the 5 services together
  artifacts/                    ← PCAP/CSV viewer
  scenario_editor/              ← Scenario config schema + loader + validator
  i18n.py                       ← Translation module (en/es)
plugins/attacks/                ← Custom Python attack scripts
tests/                          ← Unit tests (155 tests)
```

### Service layer

The live execution pipeline is split into five independently testable services, each with a single responsibility:

| Service | Responsibility | Key method |
|---------|----------------|------------|
| `CaptureService` | Find capture tool (tcpdump/tshark/dumpcap), start/stop PCAP subprocess, handle chunk rotation | `start()`, `stop()`, `find_pcap_files()` |
| `EventExecutor` | Route timeline events to the right channel (HTTP/MQTT/SSH/Local/plugin) | `fire(event_dict)` |
| `FlowExtractor` | Extract raw flow rows from PCAP(s) via NFStream (fallback: tshark) | `extract(pcap_files, flows_path)` |
| `FlowLabeler` | Assign `(src_role, dst_role, label, sublabel, kill_chain, subcategory)` to each flow | `classify(src_ip, dst_ip)`, `label(flows_path)` |
| `ArtifactManifestWriter` | Write metadata JSON manifest (with SHA-256) + execution log | `write_manifest(...)`, `save_execution_log(...)` |

The `LiveExecutionEngine` is now a thin orchestrator (~330 lines, down from ~1386) that sequences the 5 services and exposes a thread-safe snapshot for the UI. All scientific decisions (labeling logic, extraction strategy, manifest format) live in the services and can be unit-tested in isolation.

### Communication layer

A single `modules/comms/` layer replaces the previous split between `modules/communication/` (executors) and `modules/comms/` (clients). Every channel inherits from `BaseChannel` and returns a unified `ChannelResult`:

| Channel | Use | Library |
|---------|-----|---------|
| `LocalChannel` | Run shell commands on this machine (local attacks) | subprocess |
| `HTTPChannel` | REST requests to IoT devices with a web interface | urllib (stdlib) |
| `MQTTChannel` | Publish commands to an MQTT broker | paho-mqtt |
| `SSHChannel` | Execute attacks remotely on Kali Linux (with sudo/PTY support) | paramiko |

The legacy `modules/communication/` package is kept as a backwards-compatibility shim that re-exports the new symbols under the old names, so existing imports keep working.

## Attack Library

17 native attacks using real Kali Linux tools:

| Category | Attack | Tool | Requires root |
|----------|--------|------|:-------------:|
| DoS | SYN Flood | hping3 | ✓ |
| DoS | UDP Flood | hping3 | ✓ |
| DoS | ICMP Flood | hping3 | ✓ |
| DoS | TCP Flood | hping3 | ✓ |
| DoS | HTTP Slowloris | slowloris | |
| DoS | Ping Flood | nping | |
| DoS | MQTT Flood | mosquitto_pub | |
| DoS | CoAP Flood | coap-client | |
| Recon | Port Scan | nmap | |
| Recon | Vuln Scan | nmap | |
| Recon | OS Detection | nmap | ✓ |
| MITM | ARP Spoof | arpspoof | ✓ |
| MITM | ARP Spoof | ettercap | ✓ |
| Brute Force | SSH | hydra | |
| Brute Force | HTTP | hydra | |
| Brute Force | Telnet | hydra | |
| WiFi | Deauth | aireplay-ng | ✓ |

### Plugins

Custom Python scripts in `plugins/attacks/`. They are auto-detected (dependencies analyzed via AST) and run locally only.

## Supported IoT Devices

16 types with automatic HTTP endpoint and MQTT topic scanning:

camera, bulb, plug, sensor, speaker, thermostat, lock, doorbell, vacuum, tv, hub, irrigation, garage, alarm, blind, appliance.

### Endpoint scanning

- **HTTP**: 103+ endpoints from multiple vendors (Hikvision, Dahua, Shelly, Tasmota, Philips Hue, Sonoff, Axis, Foscam, Reolink, TP-Link)
- **MQTT**: Real topic discovery (subscribe `#`) + Tasmota/Zigbee2MQTT templates for all 16 types

Scan results:
- `✓` (200) → action available in the timeline
- `🔒` (401/403) → requires credentials, re-scanable with auth
- `✗` (404/500) → not available

## Communication with devices

| Protocol | Use | Library |
|----------|-----|---------|
| HTTP | REST requests to devices with a web interface | urllib (stdlib) |
| MQTT | Publish commands to the MQTT broker | paho-mqtt |
| SSH | Remote attack execution on Kali machines | paramiko |

## Outputs

Each execution produces 4 files in separate folders:

```
outputs/
  pcap/       ← Traffic capture (configurable rotation, default 500 MB)
  flows/      ← CSV with labeled flows (NFStream or tshark)
  metadata/   ← JSON with experiment configuration
  logs/       ← Execution log in plain text
```

### Flows CSV

Main fields: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bidirectional_packets`, `bidirectional_bytes`, `src_role`, `dst_role`, `flow_label`.

- `flow_label = "attack"` → flow originated from an attacker to a target
- `flow_label = "benign"` → flow between non-attacker devices
- `flow_label = "unknown"` → not classifiable

## Installation

### Requirements

- Python 3.10+
- Wireshark (Windows) or tcpdump (Linux) for packet capture
- A Kali Linux machine reachable via SSH (for remote attacks)

### Python dependencies

Dependencies are split into three files for clarity:

| File | Contents | Install command |
|------|----------|-----------------|
| `requirements/base.txt` | Runtime dependencies (end users) | `pip install -r requirements/base.txt` |
| `requirements/test.txt` | Runtime + test runner (CI, contributors) | `pip install -r requirements/test.txt` |
| `requirements/dev.txt` | Runtime + tests + linting (maintainers) | `pip install -r requirements/dev.txt` |

All pins are exact (`==`) for reproducibility. The top-level `requirements.txt` simply includes `base.txt` for backwards compatibility with `pip install -r requirements.txt`.

| Library | Version | Use |
|---------|---------|-----|
| nfstream | 9.1.0 | Network flow extraction from PCAP |
| scapy | 2.6.1 | ARP scanning + attack plugins |
| paramiko | 3.5.1 | SSH connections to attacker machines |
| paho-mqtt | 2.1.0 | MQTT communication with IoT devices |
| psutil | 7.0.0 | Network interface detection |
| python-nmap | 0.7.1 | Network device scanning |
| zeroconf | 0.146.1 | mDNS / Zeroconf discovery |
| slowloris | 0.2.0 | HTTP DoS attack |
| requests | 2.32.4 | HTTP library (some executors) |
| windows-curses | 2.4.1 | curses support on Windows (Windows only) |
| pytest | 8.4.1 | Test runner (test extra) |
| flake8 | 7.3.0 | PEP 8 compliance (dev extra) |
| pylint | 3.3.7 | Code quality score (dev extra) |

### Package metadata

The project is described by a standard `pyproject.toml` (PEP 517/518). You can install it as a package:

```bash
# Editable install, runtime only
pip install -e .

# Editable install with test dependencies
pip install -e .[test]

# Editable install with test + linting dependencies
pip install -e .[dev]
```

### Native execution (recommended for the lab)

```bash
# Windows
run.bat

# Linux/Mac
./run.sh

# Or directly
python App.py
```

The launcher scripts install Python dependencies automatically and check for Wireshark/tcpdump.

### Docker (portability and reproducibility)

```bash
# Windows
run_docker.bat

# Linux/Mac
./run_docker.sh
```

The Dockerfile uses a pinned `kalilinux/kali-rolling:2025.2` base image and pins APT package versions for reproducibility. The container includes all Kali attack tools (hping3, nmap, hydra, ettercap, etc.) pre-installed.

> **Limitation on Windows/Mac**: Docker Desktop runs an internal Linux VM.
> `--net=host` exposes the VM's interfaces, not the PC's (Wi-Fi, Ethernet).
> For traffic capture on physical interfaces, run natively (`python App.py`).
> Docker works correctly for SSH attacks to Kali, PCAP processing and analysis.
>
> On **native Linux**, `--net=host` does expose the host's real interfaces.

| Mode | Wi-Fi/Ethernet capture | SSH attacks | PCAP analysis |
|------|:----------------------:|:-----------:|:-------------:|
| Native (python App.py) | ✓ | ✓ | ✓ |
| Docker on Linux | ✓ | ✓ | ✓ |
| Docker Desktop (Win/Mac) | ✗ (VM interfaces only) | ✓ | ✓ |

## Usage

### TUI navigation

| Key | Action |
|-----|--------|
| ↑↓ | Navigate between elements |
| ←→ | Change section in the side menu |
| Enter | Edit field / open item |
| Ctrl+S | Save scenario |
| Ctrl+O | Load scenario |
| Ctrl+R | Run scenario |
| Esc | Back / cancel |

### Typical flow

1. **Devices**: Press `S` to scan the network. Assign roles (target/attacker) with `R`.
2. **Scenario**: Configure name, ID, duration, capture interface.
3. **Benign Profiles**: Add a profile (`A`), select device type → automatic endpoint scan.
4. **Attackers**: Configure SSH credentials (`P`) for remote Kali machines. Verify connection (`T`).
5. **Attack Library**: Verify available tools (`V`).
6. **Timeline**: Add events (`A`) — benign or attacks — with temporal offsets.
7. **Live**: Press `R` to run. PCAP capture starts, events fire according to the timeline.
8. **Artifacts**: Browse the generated files (PCAP, CSV).

## Software quality

```bash
# Run tests + flake8 + pylint
python tests.py
```

```
unittest : 155/155 PASSED
flake8   : 0 violations
pylint   : 10.00 / 10
```

The single entry point for local validation is `python tests.py`. It runs the unittest suite, flake8 (PEP 8 compliance) and pylint (code quality), and writes a combined report to `reports/`.

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2025 Patricio Páez, Universidad de Santiago de Chile (USACH).
