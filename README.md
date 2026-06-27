# SH-DATASET

Software de creación de datasets para evaluar sistemas de detección de intrusos en redes Smart Home IoT.

Orquestador TUI (Terminal User Interface) que coordina tráfico benigno y ataques reales sobre dispositivos IoT en una red local, capturando el tráfico resultante en formato PCAP y generando datasets CSV etiquetados listos para entrenar o evaluar un IDS.

Desarrollado como trabajo de tesis para la Universidad de Santiago de Chile (USACH).

## Descripción

SH-DATASET permite diseñar escenarios experimentales donde se combinan acciones benignas (peticiones HTTP/MQTT a dispositivos IoT reales) con ataques de red (ejecutados desde Kali Linux), capturando simultáneamente todo el tráfico de la red. El resultado es un dataset con flujos de red etiquetados como `attack`, `benign` o `unknown`, útil para entrenar y evaluar modelos de detección de intrusos.

### Flujo de trabajo

```
1. Escanear red    → descubrir dispositivos IoT en la LAN
2. Clasificar      → asignar roles (target, attacker) y tipos (camera, bulb, sensor...)
3. Crear perfiles  → escanear endpoints HTTP/MQTT disponibles en cada dispositivo
4. Diseñar timeline → programar eventos benignos y ataques con offsets temporales
5. Ejecutar        → captura PCAP + ejecución coordinada de eventos
6. Exportar        → CSV con flujos etiquetados + metadata JSON + log de ejecución
```

## Arquitectura

```
App.py                          ← Punto de entrada
design/
  Menu.py                       ← TUI principal (curses)
  Menu_*.py                     ← Secciones del menú (devices, timeline, attacks, etc.)
  handlers/                     ← Controladores de cada sección
  overlays.py                   ← Modales interactivos (selectores, inputs)
  models.py                     ← Dataclasses de la UI
modules/
  devices/                      ← Escaneo de red (nmap, ARP, scapy)
  attacks/                      ← Librería de 17 ataques + sistema de plugins
  profiles/                     ← Perfiles benignos + escáner de endpoints (103+ HTTP + MQTT)
  timeline/                     ← Gestor de eventos datetime-aware
  communication/                ← Ejecutores SSH, HTTP, MQTT
  live_executions/              ← Motor de ejecución en vivo con captura PCAP
  artifacts/                    ← Visor de PCAPs y CSVs
plugins/attacks/                ← Scripts de ataque personalizados (Python)
tests/                          ← 82 pruebas unitarias
```

## Librería de Ataques

17 ataques nativos usando herramientas reales de Kali Linux:

| Categoría | Ataque | Herramienta | Requiere root |
|-----------|--------|-------------|:-------------:|
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

Scripts Python personalizados en `plugins/attacks/`. Se verifican automáticamente (dependencias via AST) y se ejecutan solo localmente.

## Dispositivos IoT Soportados

16 tipos con escaneo automático de endpoints HTTP y topics MQTT:

camera, bulb, plug, sensor, speaker, thermostat, lock, doorbell, vacuum, tv, hub, irrigation, garage, alarm, blind, appliance.

### Escaneo de Endpoints

- **HTTP**: 103+ endpoints de múltiples fabricantes (Hikvision, Dahua, Shelly, Tasmota, Philips Hue, Sonoff, Axis, Foscam, Reolink, TP-Link)
- **MQTT**: Descubrimiento real de topics (subscribe `#`) + templates Tasmota/Zigbee2MQTT para los 16 tipos

Resultados del escaneo:
- `✓` (200) → acción disponible en el timeline
- `🔒` (401/403) → requiere credenciales, re-escaneable con auth
- `✗` (404/500) → no disponible

## Comunicación con Dispositivos

| Protocolo | Uso | Librería |
|-----------|-----|----------|
| HTTP | Peticiones REST a dispositivos con interfaz web | urllib (stdlib) |
| MQTT | Publicación de comandos al broker MQTT | paho-mqtt |
| SSH | Ejecución remota de ataques en máquinas Kali | paramiko |

## Salidas

Cada ejecución genera 4 archivos en carpetas separadas:

```
outputs/
  pcap/       ← Captura de tráfico (rotación configurable, default 500 MB)
  flows/      ← CSV con flujos etiquetados (NFStream o tshark)
  metadata/   ← JSON con configuración del experimento
  logs/       ← Log de ejecución en texto plano
```

### CSV de flujos

Campos principales: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bidirectional_packets`, `bidirectional_bytes`, `src_role`, `dst_role`, `flow_label`.

- `flow_label = "attack"` → flujo originado por un atacante hacia un target
- `flow_label = "benign"` → flujo entre dispositivos no-atacantes
- `flow_label = "unknown"` → no clasificable

## Instalación

### Requisitos

- Python 3.10+
- Wireshark (Windows) o tcpdump (Linux) para captura de paquetes
- Máquina Kali Linux accesible por SSH (para ataques remotos)

### Dependencias Python

```bash
pip install -r requirements.txt
```

| Librería | Versión | Uso |
|----------|---------|-----|
| paramiko | 5.0.0 | Conexión SSH a máquinas atacantes |
| paho-mqtt | ≥1.6 | Comunicación MQTT con dispositivos IoT |
| nfstream | 6.6.0 | Extracción de flujos de red desde PCAP |
| scapy | 2.7.0 | Escaneo ARP + plugins de ataque |
| psutil | 7.2.2 | Detección de interfaces de red |
| python-nmap | 0.7.1 | Escaneo de dispositivos en la red |
| slowloris | ≥0.2 | Ataque HTTP DoS |
| pylint | 4.0.5 | Análisis estático de código |
| flake8 | 7.3.0 | Cumplimiento PEP 8 |

### Ejecución directa

```bash
python App.py
```

### Docker (portable)

```bash
# Construir imagen con todas las herramientas de Kali
docker-compose build

# Ejecutar
docker-compose up
```

El contenedor incluye todas las herramientas de ataque (hping3, nmap, hydra, ettercap, etc.) preinstaladas. Requiere `--net=host` y `--cap-add=NET_RAW,NET_ADMIN` para acceso a la red local.

## Uso

### Navegación TUI

| Tecla | Acción |
|-------|--------|
| ↑↓ | Navegar entre elementos |
| ←→ | Cambiar sección del menú lateral |
| Enter | Editar campo / abrir elemento |
| Ctrl+S | Guardar escenario |
| Ctrl+O | Cargar escenario |
| Ctrl+R | Ejecutar escenario |
| Esc | Volver / cancelar |

### Flujo típico

1. **Devices**: Presionar `S` para escanear la red. Asignar roles (target/attacker) con `R`.
2. **Scenario**: Configurar nombre, ID, duración, interfaz de captura.
3. **Benign Profiles**: Agregar perfil (`A`), seleccionar tipo de dispositivo → escaneo automático de endpoints.
4. **Attackers**: Configurar credenciales SSH (`P`) para máquinas Kali remotas. Verificar conexión (`T`).
5. **Attack Library**: Verificar herramientas disponibles (`V`).
6. **Timeline**: Agregar eventos (`A`) — benignos o ataques — con offsets temporales.
7. **Live**: Presionar `R` para ejecutar. La captura PCAP inicia, los eventos se disparan según el timeline.
8. **Artifacts**: Explorar los archivos generados (PCAP, CSV).

## Calidad de Software

```bash
# Ejecutar tests + flake8 + pylint
python run_tests.py
```

```
unittest : 82/82 PASSED
flake8   : 0 violaciones
pylint   : 10.00 / 10
```

## Licencia

Trabajo de tesis — Universidad de Santiago de Chile (USACH), 2025.

Autor: Patricio Páez.
