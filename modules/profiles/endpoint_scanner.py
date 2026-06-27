"""
Endpoint Scanner — scans IoT devices for HTTP endpoints and MQTT topics.
Comprehensive endpoint databases for 16+ device types.
"""
from __future__ import annotations
import logging
import os
import urllib.request
import urllib.error
import base64
import concurrent.futures
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class EndpointResult:
    endpoint: str
    action_name: str = ""
    method: str = "GET"
    protocol: str = "http"
    status_code: int = 0
    available: bool = False
    needs_auth: bool = False
    unavailable: bool = False
    error: str = ""
    description: str = ""
    payload: str = ""

# ═══════════════════════════════════════════════════════════════
# ENDPOINT DATABASES
# ═══════════════════════════════════════════════════════════════


def _ep(endpoint, method="GET", desc="", payload=""):
    return {"ep": endpoint, "m": method, "desc": desc, "payload": payload}


CAMERA_ENDPOINTS = {
    "take_snapshot": [
        _ep("/snapshot", desc="Snapshot genérico"), _ep("/snapshot.cgi", desc="CGI genérico"),
        _ep("/snap.jpg", desc="JPEG directo"), _ep("/snap.cgi"), _ep("/image.jpg"),
        _ep("/image/jpeg.cgi", desc="D-Link JPEG"), _ep("/capture"), _ep("/capture.jpg"),
        _ep("/still.jpg"), _ep("/webcapture.jpg", desc="Chinese cams"),
        _ep("/tmpfs/auto.jpg"), _ep("/tmpfs/snap.jpg"), _ep("/jpg/image.jpg"),
        _ep("/ISAPI/Streaming/channels/101/picture", desc="Hikvision ISAPI"),
        _ep("/ISAPI/Streaming/channels/102/picture", desc="Hikvision ch2"),
        _ep("/Streaming/channels/1/picture", desc="Hikvision alt"),
        _ep("/cgi-bin/snapshot.cgi", desc="Dahua/Amcrest"),
        _ep("/cgi-bin/snapshot.cgi?channel=1", desc="Dahua ch1"),
        _ep("/axis-cgi/jpg/image.cgi", desc="Axis"),
        _ep("/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2", desc="Foscam"),
        _ep("/stream/snapshot", desc="TP-Link Tapo"),
        _ep("/cgi-bin/api.cgi?cmd=Snap&channel=0", desc="Reolink"),
        _ep("/onvif/snapshot", desc="ONVIF"), _ep("/onvif-http/snapshot"),
        _ep("/cgi-bin/viewer/video.jpg", desc="Vivotek"),
        _ep("/video/mjpg.cgi", desc="D-Link MJPEG"),
    ],
    "video_stream": [
        _ep("/video"), _ep("/stream"), _ep("/live"), _ep("/mjpg/video.mjpg", desc="MJPEG"),
        _ep("/video.mjpg"), _ep("/mjpeg"), _ep("/cgi-bin/mjpg/video.cgi", desc="Dahua"),
        _ep("/ISAPI/Streaming/channels/101/httpPreview", desc="Hikvision"),
        _ep("/videostream.cgi"), _ep("/axis-cgi/mjpg/video.cgi", desc="Axis"),
    ],
    "device_info": [
        _ep("/"), _ep("/status"), _ep("/system"), _ep("/deviceinfo"),
        _ep("/cgi-bin/magicBox.cgi?action=getDeviceType", desc="Dahua"),
        _ep("/ISAPI/System/deviceInfo", desc="Hikvision"),
    ],
    "ptz_control": [
        _ep("/cgi-bin/ptz.cgi?action=start&channel=0&code=Up", desc="Dahua PTZ"),
        _ep("/ISAPI/PTZCtrl/channels/1/continuous", "PUT", "Hikvision PTZ"),
        _ep("/api/ptz", "POST", "PTZ genérico"),
    ],
    "reboot": [
        _ep("/cgi-bin/magicBox.cgi?action=reboot", desc="Dahua"),
        _ep("/ISAPI/System/reboot", "PUT", "Hikvision"),
        _ep("/reboot", "POST"), _ep("/api/reboot", "POST"),
    ],
}

_RELAY_ON = [
    _ep("/relay/0?turn=on", desc="Shelly"), _ep("/cm?cmnd=Power%20On", desc="Tasmota"),
    _ep("/api/light", "POST", "API genérica", '{"state":"on"}'),
    _ep("/light/on", "POST"), _ep("/switch/on", "POST"),
    _ep("/state", "POST", "State", '{"on":true}'),
    _ep("/api/lights/1/state", "PUT", "Hue-style", '{"on":true}'),
    _ep("/zeroconf/switch", "POST", "Sonoff DIY", '{"data":{"switch":"on"}}'),
]
_RELAY_OFF = [
    _ep("/relay/0?turn=of", desc="Shelly"), _ep("/cm?cmnd=Power%20Of", desc="Tasmota"),
    _ep("/api/light", "POST", "API genérica", '{"state":"off"}'),
    _ep("/light/of", "POST"), _ep("/switch/of", "POST"),
    _ep("/state", "POST", "State", '{"on":false}'),
    _ep("/zeroconf/switch", "POST", "Sonoff DIY", '{"data":{"switch":"off"}}'),
]
_STATUS = [
    _ep("/status", desc="Status genérico"), _ep("/relay/0", desc="Shelly status"),
    _ep("/cm?cmnd=Status%200", desc="Tasmota"), _ep("/api/state"),
    _ep("/settings", desc="Shelly settings"),
]

BULB_ENDPOINTS = {
    "turn_on": _RELAY_ON,
    "turn_of": _RELAY_OFF,
    "toggle": [_ep("/relay/0?turn=toggle", desc="Shelly"), _ep("/cm?cmnd=Power%20Toggle", desc="Tasmota"),
               _ep("/api/light/toggle", "POST")],
    "set_brightness": [
        _ep("/light/brightness", "POST", payload='{"brightness":50}'),
        _ep("/cm?cmnd=Dimmer%2050", desc="Tasmota"), _ep("/light/0?brightness=50", desc="Shelly"),
    ],
    "set_color": [
        _ep("/cm?cmnd=Color%20FF0000", desc="Tasmota RGB"),
        _ep("/light/0?red=255&green=0&blue=0", desc="Shelly RGB"),
        _ep("/api/lights/1/state", "PUT", "Hue color", '{"hue":0,"sat":254}'),
    ],
    "status": _STATUS,
}

PLUG_ENDPOINTS = {
    "turn_on": _RELAY_ON, "turn_of": _RELAY_OFF,
    "toggle": BULB_ENDPOINTS["toggle"], "status": _STATUS,
    "read_power": [
        _ep("/meter/0", desc="Shelly meter"), _ep("/cm?cmnd=Status%208", desc="Tasmota energy"),
        _ep("/api/energy"), _ep("/emeter/0", desc="Shelly emeter"),
        _ep("/rpc/Switch.GetStatus?id=0", desc="Shelly Gen2"),
    ],
}

SENSOR_ENDPOINTS = {
    "read_data": [
        _ep("/status"), _ep("/sensor/data"), _ep("/api/sensor"),
        _ep("/cm?cmnd=Status%2010", desc="Tasmota sensor"),
        _ep("/data"), _ep("/api/data"), _ep("/rpc/Sensor.GetStatus", desc="Shelly sensor"),
    ],
    "status": _STATUS,
}

SPEAKER_ENDPOINTS = {
    "play_audio": [_ep("/api/audio/play", "POST"), _ep("/playback", "POST"), _ep("/player/play", "POST")],
    "set_volume": [_ep("/api/audio/volume", "POST", payload='{"volume":50}'), _ep("/volume", "POST",
                                                                                  payload='{"level":50}')],
    "stop_audio": [_ep("/api/audio/stop", "POST"), _ep("/player/stop", "POST")],
    "status": _STATUS,
}

THERMOSTAT_ENDPOINTS = {
    "get_temperature": [
        _ep("/api/thermostat"), _ep("/thermostat/status"), _ep("/api/temperature"),
        _ep("/status"), _ep("/cm?cmnd=Status%2010", desc="Tasmota"),
    ],
    "set_temperature": [
        _ep("/api/thermostat", "POST", payload='{"target_temp":22}'),
        _ep("/thermostat/target", "POST", payload='{"temperature":22}'),
    ],
    "set_mode": [
        _ep("/api/thermostat/mode", "POST", payload='{"mode":"heat"}'),
        _ep("/thermostat/mode", "POST", payload='{"mode":"auto"}'),
    ],
    "status": _STATUS,
}

LOCK_ENDPOINTS = {
    "lock": [
        _ep("/api/lock", "POST", payload='{"state":"locked"}'),
        _ep("/lock", "POST"), _ep("/api/lock/engage", "POST"),
    ],
    "unlock": [
        _ep("/api/lock", "POST", payload='{"state":"unlocked"}'),
        _ep("/unlock", "POST"), _ep("/api/lock/disengage", "POST"),
    ],
    "status": [_ep("/api/lock/status"), _ep("/lock/status"), _ep("/status")],
}

DOORBELL_ENDPOINTS = {
    "take_snapshot": CAMERA_ENDPOINTS["take_snapshot"][:10],
    "video_stream": CAMERA_ENDPOINTS["video_stream"][:5],
    "device_info": [_ep("/"), _ep("/status"), _ep("/api/info")],
    "ring_event": [_ep("/api/events/ring"), _ep("/events")],
}

VACUUM_ENDPOINTS = {
    "start_clean": [
        _ep("/api/start", "POST"), _ep("/api/clean/start", "POST"),
        _ep("/robot/start", "POST"),
    ],
    "stop_clean": [
        _ep("/api/stop", "POST"), _ep("/api/clean/stop", "POST"),
        _ep("/robot/stop", "POST"),
    ],
    "go_home": [
        _ep("/api/home", "POST"), _ep("/api/dock", "POST"),
        _ep("/robot/dock", "POST"),
    ],
    "status": [_ep("/api/status"), _ep("/robot/status"), _ep("/status")],
}

TV_ENDPOINTS = {
    "power_on": [_ep("/api/power/on", "POST"), _ep("/power", "POST", payload='{"state":"on"}')],
    "power_of": [_ep("/api/power/of", "POST"), _ep("/power", "POST", payload='{"state":"off"}')],
    "set_volume": [_ep("/api/volume", "POST", payload='{"level":20}'), _ep("/volume", "POST")],
    "set_input": [_ep("/api/input", "POST", payload='{"input":"hdmi1"}')],
    "status": [_ep("/api/info"), _ep("/status"), _ep("/")],
}

HUB_ENDPOINTS = {
    "device_list": [
        _ep("/api/devices"), _ep("/devices"), _ep("/api/nodes"),
        _ep("/zigbee/devices", desc="Zigbee"), _ep("/zwave/devices", desc="Z-Wave"),
    ],
    "status": [_ep("/api/status"), _ep("/status"), _ep("/api/info"), _ep("/")],
}

IRRIGATION_ENDPOINTS = {
    "start_zone": [
        _ep("/api/zone/1/start", "POST"), _ep("/relay/0?turn=on", desc="Shelly relay"),
        _ep("/api/irrigation/start", "POST"),
    ],
    "stop_zone": [
        _ep("/api/zone/1/stop", "POST"), _ep("/relay/0?turn=of"),
        _ep("/api/irrigation/stop", "POST"),
    ],
    "status": _STATUS,
}

GARAGE_ENDPOINTS = {
    "open": [_ep("/api/door/open", "POST"), _ep("/relay/0?turn=on", desc="Shelly relay"), _ep("/open", "POST")],
    "close": [_ep("/api/door/close", "POST"), _ep("/relay/0?turn=of"), _ep("/close", "POST")],
    "status": [_ep("/api/door/status"), _ep("/status")],
}

ALARM_ENDPOINTS = {
    "arm": [_ep("/api/alarm/arm", "POST"), _ep("/arm", "POST")],
    "disarm": [_ep("/api/alarm/disarm", "POST"), _ep("/disarm", "POST")],
    "status": [_ep("/api/alarm/status"), _ep("/status")],
    "trigger": [_ep("/api/alarm/trigger", "POST")],
}

BLIND_ENDPOINTS = {
    "open": [_ep("/api/cover/open", "POST"), _ep("/roller/0?go=open", desc="Shelly"), _ep("/open", "POST")],
    "close": [_ep("/api/cover/close", "POST"), _ep("/roller/0?go=close", desc="Shelly"), _ep("/close", "POST")],
    "set_position": [
        _ep("/api/cover/position", "POST", payload='{"position":50}'),
        _ep("/roller/0?go=to_pos&roller_pos=50", desc="Shelly"),
    ],
    "status": [_ep("/roller/0", desc="Shelly"), _ep("/api/cover/status"), _ep("/status")],
}

APPLIANCE_ENDPOINTS = {
    "power_on": _RELAY_ON[:4],
    "power_of": _RELAY_OFF[:4],
    "status": _STATUS,
    "get_program": [_ep("/api/program"), _ep("/api/status"), _ep("/status")],
}

# ── MQTT TOPICS per device type ────────────────────────────────

MQTT_TOPICS = {
    "bulb": {
        "turn_on": {"topic": "cmnd/{device}/POWER", "payload": "ON", "desc": "Tasmota MQTT on"},
        "turn_off": {"topic": "cmnd/{device}/POWER", "payload": "OFF", "desc": "Tasmota MQTT off"},
        "status": {"topic": "stat/{device}/STATUS", "payload": "", "desc": "Tasmota status"},
    },
    "plug": {
        "turn_on": {"topic": "cmnd/{device}/POWER", "payload": "ON"},
        "turn_off": {"topic": "cmnd/{device}/POWER", "payload": "OFF"},
        "status": {"topic": "stat/{device}/STATUS", "payload": ""},
    },
    "sensor": {
        "read_data": {"topic": "tele/{device}/SENSOR", "payload": "", "desc": "Tasmota telemetry"},
        "read_temperature": {"topic": "{device}/temperature", "payload": ""},
        "read_humidity": {"topic": "{device}/humidity", "payload": ""},
        "read_motion": {"topic": "{device}/motion", "payload": ""},
    },
    "thermostat": {
        "get_temperature": {"topic": "{device}/temperature", "payload": ""},
        "set_temperature": {"topic": "{device}/set_temperature", "payload": "22"},
    },
    "alarm": {
        "arm": {"topic": "{device}/arm", "payload": "ARM"},
        "disarm": {"topic": "{device}/disarm", "payload": "DISARM"},
    },
}

# ═══════════════════════════════════════════════════════════════

ENDPOINT_DB = {
    "camera": CAMERA_ENDPOINTS, "bulb": BULB_ENDPOINTS, "plug": PLUG_ENDPOINTS,
    "sensor": SENSOR_ENDPOINTS, "speaker": SPEAKER_ENDPOINTS, "thermostat": THERMOSTAT_ENDPOINTS,
    "lock": LOCK_ENDPOINTS, "doorbell": DOORBELL_ENDPOINTS, "vacuum": VACUUM_ENDPOINTS,
    "tv": TV_ENDPOINTS, "hub": HUB_ENDPOINTS, "irrigation": IRRIGATION_ENDPOINTS,
    "garage": GARAGE_ENDPOINTS, "alarm": ALARM_ENDPOINTS, "blind": BLIND_ENDPOINTS,
    "appliance": APPLIANCE_ENDPOINTS,
}


# ═══════════════════════════════════════════════════════════════
# SCANNER
# ═══════════════════════════════════════════════════════════════

def _optimal_workers() -> int:
    """Dynamic thread count based on system CPU."""
    try:
        cpus = os.cpu_count() or 4
        return min(cpus * 3, 20)  # 3x CPUs, max 20
    except Exception:
        return 8


def scan_endpoints(device_ip, device_type, port=80, timeout=1.5,
                   auth_user="", auth_pass="", log_fn=None):
    db = ENDPOINT_DB.get(device_type, {})
    if not db:
        if log_fn:
            log_fn(f"Sin endpoints para '{device_type}'", "WARN")
        return {}

    workers = _optimal_workers()
    if log_fn:
        log_fn(f"  Threads: {workers} | Timeout: {timeout}s", "INFO")

    results = {}
    all_tasks = []
    for action_name, endpoints in db.items():
        for ep_info in endpoints:
            all_tasks.append((action_name, ep_info))

    if log_fn:
        log_fn(f"  Total: {len(all_tasks)} endpoints a probar", "INFO")

    completed = [0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {}
        for action_name, ep_info in all_tasks:
            f = executor.submit(
                _probe_endpoint, device_ip, port,
                ep_info["ep"], ep_info.get("m", "GET"),
                ep_info.get("payload", ""), timeout, auth_user, auth_pass,
            )
            future_map[f] = (action_name, ep_info)

        for future in concurrent.futures.as_completed(future_map):
            action_name, ep_info = future_map[future]
            result = future.result()
            result.action_name = action_name
            result.description = ep_info.get("desc", "")
            result.payload = ep_info.get("payload", "")
            results.setdefault(action_name, []).append(result)
            completed[0] += 1

            if log_fn:
                if result.available:
                    log_fn(f"  ✓ {action_name}: {result.endpoint} → {result.status_code}", "OK")
                elif result.needs_auth:
                    log_fn(f"  🔒 {action_name}: {result.endpoint} → {result.status_code}", "WARN")

    if log_fn:
        log_fn(f"  Completado: {completed[0]}/{len(all_tasks)} endpoints", "INFO")
    return results


def scan_mqtt(device_ip, device_type, port=1883, timeout=3.0, log_fn=None):
    """Try MQTT connection and discover available topics."""
    topics = MQTT_TOPICS.get(device_type, {})
    if not topics:
        return {}
    results = {}
    try:
        import paho.mqtt.client as mqtt
        client = mqtt.Client()
        connected = [False]

        def on_connect(c, u, f, rc):
            connected[0] = rc == 0
        client.on_connect = on_connect
        client.connect(device_ip, port, keepalive=int(timeout))
        client.loop_start()
        import time
        time.sleep(min(timeout, 2))
        client.loop_stop()
        client.disconnect()
        if connected[0]:
            if log_fn:
                log_fn(f"  MQTT broker conectado en {device_ip}:{port}", "OK")
            for action_name, info in topics.items():
                results[action_name] = EndpointResult(
                    endpoint=info["topic"], action_name=action_name,
                    method="PUB", protocol="mqtt", available=True,
                    description=info.get("desc", "MQTT topic"),
                    payload=info.get("payload", ""),
                )
            return results
        else:
            if log_fn:
                log_fn(f"  MQTT no disponible en {device_ip}:{port}", "INFO")
    except ImportError:
        if log_fn:
            log_fn("  paho-mqtt no instalado (pip install paho-mqtt)", "WARN")
    except Exception as e:
        if log_fn:
            log_fn(f"  MQTT error: {e}", "INFO")
    return {}


def _probe_endpoint(ip, port, endpoint, method, payload, timeout, auth_user, auth_pass):
    url = f"http://{ip}:{port}{endpoint}"
    result = EndpointResult(endpoint=endpoint, method=method, protocol="http")
    try:
        data = payload.encode() if payload and method in ("POST", "PUT") else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "SH-DATASET/1.0")
        if auth_user:
            creds = base64.b64encode(f"{auth_user}:{auth_pass}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
        with urllib.request.urlopen(req, timeout=min(timeout, 2.0)) as resp:
            result.status_code = resp.status
            result.available = True
    except urllib.error.HTTPError as e:
        result.status_code = e.code
        if e.code in (401, 403):
            result.needs_auth = True
        else:
            result.unavailable = True
    except (OSError, TimeoutError, ValueError):
        result.unavailable = True
    return result


def summarize_scan(results):
    summary = {}
    for action, ep_results in results.items():
        available = [r for r in ep_results if r.available]
        needs_auth = [r for r in ep_results if r.needs_auth]
        if available:
            best = available[0]
            summary[action] = {"status": "available", "endpoint": best.endpoint,
                               "method": best.method, "desc": best.description,
                               "status_code": best.status_code, "protocol": best.protocol,
                               "payload": best.payload}
        elif needs_auth:
            best = needs_auth[0]
            summary[action] = {"status": "needs_auth", "endpoint": best.endpoint,
                               "method": best.method, "desc": best.description,
                               "status_code": best.status_code, "protocol": best.protocol,
                               "payload": best.payload}
        else:
            summary[action] = {"status": "unavailable", "endpoint": "", "method": "",
                               "desc": "", "status_code": 0, "protocol": "http", "payload": ""}
    return summary
