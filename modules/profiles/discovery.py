"""
Entrada: None
Salida: Active discovery module
Descripción: Active endpoint discovery — adds three layers on top of the
             existing static dictionary:

             1) HTTP fingerprinting: identifies vendor/firmware from Server
                header, favicon hash and known response patterns, then
                selects the relevant subset of endpoints.
             2) HTTP crawling: when a 200/301 is found, parses the HTML/JSON
                response for new paths (links, /api/ references, JS bundles)
                and probes them.
             3) HTTP parameter fuzzing: for endpoints that responded, tries
                common IoT parameters (?debug=1, ?cmd=, ?action=).
             4) MQTT active probing: subscribes to # for a configurable
                window AND publishes probes to known command topics
                (cmnd/+/POWER, cmnd/+/status) to force sleeping devices
                to reply. Also listens to $SYS/# for broker metadata.
"""
from __future__ import annotations
import base64
import hashlib
import json
import logging
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ─── Vendor fingerprints ───────────────────────────────────────────────────

# Server header → vendor mapping
SERVER_VENDORS: dict[str, str] = {
    "hikvision": "hikvision",
    "dahua": "dahua",
    "amcrest": "dahua",
    "shelly": "shelly",
    "tasmota": "tasmota",
    "sonoff": "sonoff",
    "bosch": "bosch",
    "axis": "axis",
    "foscam": "foscam",
    "reolink": "reolink",
    "tp-link": "tplink",
    "tp link": "tplink",
    "kasa": "tplink",
    "tapo": "tplink",
    "philips": "philips",
    "hue": "philips",
    "d-link": "dlink",
    "dlink": "dlink",
    "vivotek": "vivotek",
    "ubiquiti": "ubiquiti",
    "unifi": "ubiquiti",
    "espressif": "espressif",
    "esp8266": "espressif",
    "esp32": "espressif",
    "tuya": "tuya",
    "goke": "goke",
    "xm": "xm",
    "iegeek": "iegeek",
}

# Favicon hash → vendor (computed from /favicon.ico)
# These are well-known IoT device favicons; extend as you discover more.
FAVICON_VENDORS: dict[str, str] = {
    # Empty placeholder — hashes are computed at runtime and logged
    # so the operator can add them here after observing real devices.
}

# Vendor → endpoint path prefixes (used to filter the static dictionary)
VENDOR_ENDPOINT_PREFIXES: dict[str, list[str]] = {
    "hikvision": ["/ISAPI/"],
    "dahua": ["/cgi-bin/"],
    "amcrest": ["/cgi-bin/"],
    "shelly": ["/relay/", "/meter/", "/roller/", "/rpc/", "/settings", "/status"],
    "tasmota": ["/cm?"],
    "sonoff": ["/zeroconf/"],
    "axis": ["/axis-cgi/"],
    "foscam": ["/cgi-bin/CGIProxy"],
    "reolink": ["/cgi-bin/api"],
    "tplink": ["/stream/", "/cgi-bin/"],
    "philips": ["/api/lights/"],
    "dlink": ["/image/", "/video/"],
    "vivotek": ["/cgi-bin/viewer/"],
}

# Generic paths to probe when no vendor is identified
GENERIC_DISCOVERY_PATHS: list[str] = [
    "/", "/api", "/api/v1", "/api/status", "/api/info",
    "/status", "/info", "/system", "/device", "/deviceinfo",
    "/config", "/settings", "/health", "/version",
    "/swagger", "/docs", "/openapi.json", "/api-docs",
    "/login", "/admin", "/setup", "/wizard",
    "/onvif/device_service", "/live", "/stream",
    "/cgi-bin/luci", "/cgi-bin/webcm",
]

# Common IoT query parameters to fuzz on discovered endpoints
COMMON_PARAMS: list[str] = [
    "debug", "cmd", "action", "state", "status",
    "value", "set", "get", "mode", "power",
    "on", "off", "toggle", "reset", "reboot",
    "channel", "id", "type", "name", "level",
]


# ─── Data classes ──────────────────────────────────────────────────────────

@dataclass
class DeviceFingerprint:
    """
    Entrada: None
    Salida: DeviceFingerprint instance
    Descripción: Holds the vendor/firmware fingerprint of a device.
    """
    vendor: str = ""
    server_header: str = ""
    favicon_hash: str = ""
    firmware_hint: str = ""
    confidence: str = "low"  # low | medium | high
    source: str = ""  # server_header | favicon | response_pattern


@dataclass
class CrawledEndpoint:
    """
    Entrada: None
    Salida: CrawledEndpoint instance
    Descripción: A path discovered by crawling a 200/301 response.
    """
    path: str
    source: str = ""  # html_link | json_ref | js_bundle
    status_code: int = 0
    available: bool = False


@dataclass
class DiscoveryResult:
    """
    Entrada: None
    Salida: DiscoveryResult instance
    Descripción: Aggregated result of the active discovery phase.
    """
    fingerprint: DeviceFingerprint = field(default_factory=DeviceFingerprint)
    crawled_endpoints: list[CrawledEndpoint] = field(default_factory=list)
    fuzzed_params: dict[str, list[str]] = field(default_factory=dict)
    mqtt_active_topics: list[str] = field(default_factory=list)
    mqtt_sys_info: dict = field(default_factory=dict)


# ─── HTTP fingerprinting ──────────────────────────────────────────────────

"""
Entrada: device_ip (str), port (int), timeout (float), log_fn (callable | None)
Salida: DeviceFingerprint
Descripción: Identifies the device vendor by examining the Server header,
             favicon hash and known response patterns.
"""
def fingerprint_device(
    device_ip: str,
    port: int = 80,
    timeout: float = 2.0,
    log_fn: Optional[Callable[[str, str], None]] = None,
) -> DeviceFingerprint:
    fp = DeviceFingerprint()

    # 1) Try to get the Server header from the root URL
    try:
        url = f"http://{device_ip}:{port}/"
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "SH-DATASET/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            server = resp.headers.get("Server", "")
            fp.server_header = server
            if server:
                server_lower = server.lower()
                for keyword, vendor in SERVER_VENDORS.items():
                    if keyword in server_lower:
                        fp.vendor = vendor
                        fp.confidence = "medium"
                        fp.source = "server_header"
                        break
    except urllib.error.HTTPError as e:
        # Even on error, we might get a Server header
        fp.server_header = e.headers.get("Server", "")
        if fp.server_header:
            server_lower = fp.server_header.lower()
            for keyword, vendor in SERVER_VENDORS.items():
                if keyword in server_lower:
                    fp.vendor = vendor
                    fp.confidence = "medium"
                    fp.source = "server_header"
                    break
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        pass

    # 2) Try to get the favicon hash
    try:
        url = f"http://{device_ip}:{port}/favicon.ico"
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "SH-DATASET/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            favicon_data = resp.read()
            if favicon_data:
                # Use MMH3-compatible hash (used by Shodan)
                # We use MD5 as a fallback since mmh3 may not be installed
                fp.favicon_hash = hashlib.md5(favicon_data).hexdigest()
                if fp.favicon_hash in FAVICON_VENDORS:
                    fp.vendor = FAVICON_VENDORS[fp.favicon_hash]
                    fp.confidence = "high"
                    fp.source = "favicon"
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        pass

    if log_fn and fp.vendor:
        log_fn(
            f"  Fingerprint: vendor={fp.vendor} "
            f"(confidence={fp.confidence}, source={fp.source})",
            "INFO",
        )
    elif log_fn and fp.server_header:
        log_fn(f"  Fingerprint: Server='{fp.server_header}' (vendor unknown)", "INFO")

    return fp


# ─── HTTP crawling ────────────────────────────────────────────────────────

# Regex to find paths in HTML/JSON responses
_PATH_PATTERNS = [
    re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/[a-zA-Z0-9_/.-]+)["\']'),  # JSON-style "/api/..."
    re.compile(r'url\(["\']?([^"\')\s]+)["\']?\)', re.IGNORECASE),  # CSS url()
]


"""
Entrada: body (str), base_url (str)
Salida: list[str]
Descripción: Extracts candidate paths from an HTML/JSON response body.
             Returns a de-duplicated list of absolute paths.
"""
def extract_paths_from_response(body: str, base_url: str = "") -> list[str]:
    paths = set()
    for pattern in _PATH_PATTERNS:
        for match in pattern.findall(body):
            if not match or len(match) < 2:
                continue
            # Normalize: only keep paths that start with /
            if match.startswith("/"):
                # Strip query string and fragment
                clean = match.split("?")[0].split("#")[0]
                if len(clean) > 1 and not clean.endswith("/"):
                    paths.add(clean)
                elif len(clean) > 1:
                    paths.add(clean.rstrip("/"))
            elif not match.startswith("http") and not match.startswith("//"):
                # Relative path
                clean = "/" + match.lstrip("/")
                clean = clean.split("?")[0].split("#")[0]
                if len(clean) > 1:
                    paths.add(clean.rstrip("/"))
    return sorted(paths)


"""
Entrada: device_ip (str), port (int), seed_paths (list[str]), timeout (float), log_fn (callable | None), auth_user (str), auth_pass (str)
Salida: list[CrawledEndpoint]
Descripción: Probes a list of seed paths and, for each 200/301 response,
             crawls the body to discover additional paths. Returns the
             list of crawled endpoints that responded.
"""
def crawl_endpoints(
    device_ip: str,
    port: int = 80,
    seed_paths: Optional[list[str]] = None,
    timeout: float = 1.5,
    log_fn: Optional[Callable[[str, str], None]] = None,
    auth_user: str = "",
    auth_pass: str = "",
) -> list[CrawledEndpoint]:
    if seed_paths is None:
        seed_paths = GENERIC_DISCOVERY_PATHS

    discovered: list[CrawledEndpoint] = []
    probed: set[str] = set()

    def _probe_and_crawl(path: str, source: str = "seed") -> None:
        if path in probed:
            return
        probed.add(path)

        url = f"http://{device_ip}:{port}{path}"
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "SH-DATASET/1.0")
            if auth_user:
                creds = base64.b64encode(
                    f"{auth_user}:{auth_pass}".encode()
                ).decode()
                req.add_header("Authorization", f"Basic {creds}")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                ep = CrawledEndpoint(
                    path=path, source=source,
                    status_code=resp.status, available=True,
                )
                discovered.append(ep)
                if log_fn:
                    log_fn(f"  🔍 Crawled: {path} → {resp.status}", "INFO")

                # Extract new paths from the response and recurse (depth 1)
                new_paths = extract_paths_from_response(body, url)
                for np in new_paths[:20]:  # cap to avoid explosion
                    if np not in probed:
                        _probe_and_crawl(np, source="crawl")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                discovered.append(CrawledEndpoint(
                    path=path, source=source,
                    status_code=e.code, available=False,
                ))
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            pass

    for path in seed_paths:
        _probe_and_crawl(path)

    if log_fn and discovered:
        log_fn(
            f"  Crawl: {len(discovered)} endpoints discovered "
            f"({sum(1 for e in discovered if e.available)} available)",
            "INFO",
        )

    return discovered


# ─── HTTP parameter fuzzing ───────────────────────────────────────────────

"""
Entrada: device_ip (str), port (int), endpoint (str), timeout (float), log_fn (callable | None)
Salida: list[str]
Descripción: Fuzzes common IoT query parameters on the given endpoint.
             Returns the list of parameters that changed the response
             (different status code or body length).
"""
def fuzz_parameters(
    device_ip: str,
    port: int,
    endpoint: str,
    timeout: float = 1.5,
    log_fn: Optional[Callable[[str, str], None]] = None,
) -> list[str]:
    # Get baseline response
    baseline_status = 0
    baseline_length = 0
    try:
        url = f"http://{device_ip}:{port}{endpoint}"
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "SH-DATASET/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            baseline_status = resp.status
            baseline_length = len(resp.read())
    except urllib.error.HTTPError as e:
        baseline_status = e.code
        try:
            baseline_length = len(e.read())
        except Exception:  # pylint: disable=broad-exception-caught
            pass
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return []

    effective_params: list[str] = []
    for param in COMMON_PARAMS:
        try:
            url = f"http://{device_ip}:{port}{endpoint}?{param}=1"
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "SH-DATASET/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                if resp.status != baseline_status or len(body) != baseline_length:
                    effective_params.append(param)
        except urllib.error.HTTPError as e:
            if e.code != baseline_status:
                effective_params.append(param)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            continue

    if log_fn and effective_params:
        log_fn(
            f"  🔍 Fuzzed {endpoint}: {len(effective_params)} params "
            f"changed response ({', '.join(effective_params[:5])})",
            "INFO",
        )

    return effective_params


# ─── MQTT active probing ──────────────────────────────────────────────────

# Probe topics to publish (forces devices to reply on their stat/tele topics)
_MQTT_PROBE_TOPICS: list[str] = [
    "cmnd/+/POWER",
    "cmnd/+/status",
    "cmnd/+/STATE",
    "cmnd/+/STATUS",
    "cmnd/+/STATUS8",
    "cmnd/+/STATUS10",
    # Zigbee2MQTT bridges
    "zigbee2mqtt/bridge/config/devices/get",
    "zigbee2mqtt/bridge/config/permit_join",
]

# $SYS topics to monitor for broker metadata
_SYS_TOPICS: list[str] = [
    "$SYS/broker/clients/total",
    "$SYS/broker/clients/maximum",
    "$SYS/broker/subscriptions/count",
    "$SYS/broker/retained messages/count",
    "$SYS/broker/load/messages/+",
    "$SYS/#",
]


"""
Entrada: device_ip (str), port (int), listen_window (float), log_fn (callable | None)
Salida: tuple[list[str], dict]
Descripción: Connects to the MQTT broker, subscribes to # and $SYS/#,
             publishes probe commands to known cmnd topics to force
             sleeping devices to reply, and listens for listen_window
             seconds. Returns (discovered_topics, sys_info).
"""
def mqtt_active_discovery(
    device_ip: str,
    port: int = 1883,
    listen_window: float = 10.0,
    log_fn: Optional[Callable[[str, str], None]] = None,
) -> tuple[list[str], dict]:
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        if log_fn:
            log_fn("  paho-mqtt not installed (pip install paho-mqtt)", "WARN")
        return [], {}

    discovered_topics: set[str] = set()
    sys_info: dict = {}
    messages: list[tuple[str, str]] = []

    client = mqtt.Client()
    connected = [False]

    def on_connect(c, u, f, rc):
        connected[0] = (rc == 0)
        if connected[0]:
            # Subscribe to everything
            c.subscribe("#")
            c.subscribe("$SYS/#")

    def on_message(c, u, msg):
        topic = msg.topic
        payload = msg.payload.decode("utf-8", errors="replace")
        messages.append((topic, payload))
        if topic.startswith("$SYS/"):
            sys_info[topic] = payload
        else:
            discovered_topics.add(topic)

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(device_ip, port, keepalive=int(listen_window) + 5)
        client.loop_start()

        # Wait for connection
        time.sleep(1)
        if not connected[0]:
            if log_fn:
                log_fn(f"  MQTT active discovery: not connected to {device_ip}:{port}", "INFO")
            client.loop_stop()
            client.disconnect()
            return [], {}

        if log_fn:
            log_fn(
                f"  MQTT active discovery: listening for {listen_window}s "
                f"+ publishing {len(_MQTT_PROBE_TOPICS)} probes",
                "INFO",
            )

        # Phase 1: passive listen (first half of the window)
        time.sleep(listen_window / 2)

        # Phase 2: publish probes to force replies
        for probe_topic in _MQTT_PROBE_TOPICS:
            try:
                client.publish(probe_topic, "", qos=0)
            except Exception:  # pylint: disable=broad-exception-caught
                pass

        # Phase 3: listen for replies (second half of the window)
        time.sleep(listen_window / 2)

        client.loop_stop()
        client.disconnect()

        if log_fn:
            log_fn(
                f"  MQTT active discovery: {len(discovered_topics)} topics found, "
                f"{len(sys_info)} $SYS entries",
                "OK",
            )
            for t in sorted(discovered_topics)[:10]:
                log_fn(f"    topic: {t}", "INFO")

        return sorted(discovered_topics), sys_info

    except (OSError, ConnectionError, TimeoutError, ValueError) as e:
        if log_fn:
            log_fn(f"  MQTT active discovery error: {e}", "INFO")
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return [], {}


# ─── Full discovery pipeline ──────────────────────────────────────────────

"""
Entrada: device_ip (str), port (int), device_type (str), timeout (float), auth_user (str), auth_pass (str), mqtt_port (int), mqtt_window (float), log_fn (callable | None)
Salida: DiscoveryResult
Descripción: Runs the full active discovery pipeline:
             1. Fingerprint the device vendor
             2. Crawl generic paths + vendor-specific paths
             3. Fuzz parameters on discovered endpoints
             4. MQTT active discovery (probes + $SYS)
             Returns the aggregated DiscoveryResult.
"""
def run_active_discovery(
    device_ip: str,
    port: int = 80,
    device_type: str = "",
    timeout: float = 2.0,
    auth_user: str = "",
    auth_pass: str = "",
    mqtt_port: int = 1883,
    mqtt_window: float = 10.0,
    log_fn: Optional[Callable[[str, str], None]] = None,
) -> DiscoveryResult:
    result = DiscoveryResult()

    # Phase 1: Fingerprint
    if log_fn:
        log_fn("  Phase 1: HTTP fingerprinting…", "INFO")
    result.fingerprint = fingerprint_device(device_ip, port, timeout, log_fn)

    # Phase 2: Crawl (use generic + vendor-specific paths)
    if log_fn:
        log_fn("  Phase 2: HTTP crawling…", "INFO")
    seed_paths = list(GENERIC_DISCOVERY_PATHS)
    if result.fingerprint.vendor:
        vendor_prefixes = VENDOR_ENDPOINT_PREFIXES.get(
            result.fingerprint.vendor, []
        )
        seed_paths.extend(vendor_prefixes)
    result.crawled_endpoints = crawl_endpoints(
        device_ip, port, seed_paths=seed_paths,
        timeout=timeout, log_fn=log_fn,
        auth_user=auth_user, auth_pass=auth_pass,
    )

    # Phase 3: Parameter fuzzing (on available crawled endpoints)
    if log_fn:
        log_fn("  Phase 3: HTTP parameter fuzzing…", "INFO")
    for ep in result.crawled_endpoints:
        if ep.available:
            params = fuzz_parameters(device_ip, port, ep.path, timeout, log_fn)
            if params:
                result.fuzzed_params[ep.path] = params

    # Phase 4: MQTT active discovery
    if mqtt_port:
        if log_fn:
            log_fn("  Phase 4: MQTT active discovery…", "INFO")
        topics, sys_info = mqtt_active_discovery(
            device_ip, mqtt_port, mqtt_window, log_fn,
        )
        result.mqtt_active_topics = topics
        result.mqtt_sys_info = sys_info

    return result
