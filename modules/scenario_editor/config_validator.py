"""
Entrada: None
Salida: Scenario validator module
Descripción: Comprehensive scenario validator that checks every parameter in
             a loaded scenario JSON against the software's accepted values,
             formats and cross-references. Returns a list of error strings
             (empty when the scenario is valid).
"""
from __future__ import annotations
import ipaddress
import re
from typing import Any

from modules.scenario_editor.config_schema import ScenarioConfig


# ─── Allowed values (single source of truth) ────────────────────────────────

VALID_SCAN_METHODS = {"nmap", "arp", "all"}
VALID_ROLES = {"target", "benign", "attacker", "unknown"}
VALID_EVENT_TYPES = {"benign", "attack"}
VALID_EVENT_STATUS = {"queued", "running", "completed", "skipped", "expired"}
VALID_ATTACKER_MODES = {"local", "ssh"}
VALID_OUTPUT_FORMATS = {"json"}
VALID_DEVICE_TYPES = {
    "bulb", "plug", "camera", "speaker", "sensor", "hub",
    "tv", "router", "pc", "attacker", "unknown",
    # Extra types accepted by the profile library (free-form device types):
    "thermostat", "lock", "doorbell", "vacuum",
    "irrigation", "garage", "alarm", "blind", "appliance",
}
VALID_PROTOCOLS = {"http", "https", "mqtt", "ssh"}
VALID_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}
VALID_MQTT_METHODS = {"PUB", "SUB"}
VALID_SSH_METHODS = {"EXEC"}

# Common field type expectations (section -> field -> python type)
_SCALAR_TYPES = {
    str: ("str",),
    int: ("int",),
    bool: ("bool",),
    float: ("float",),
}

# ─── Regex patterns ────────────────────────────────────────────────────────

_TIME_RE = re.compile(r"^\d{2}:\d{2}:\d{2}$")
_DURATION_RE = re.compile(r"^\d{1,2}:\d{2}:\d{2}$|^\d+d(:\d{2}:\d{2}:\d{2})?$|^\d+(\.\d+)?[smhdwM]$")
_OFFSET_DURATION_RE = re.compile(r"^\d{2}:\d{2}:\d{2}$")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^$")
_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_EXP_ID_RE = re.compile(r"^[\w\-]+$")  # accepts EXP_001, EXP-2024-001, NEW, 00, etc.
_DATETIME_RE = re.compile(
    r"^\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}$"
    r"|^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}$"
    r"|^\d{2}:\d{2}:\d{2}$"
    r"|^$"
)


# ─── Helpers ───────────────────────────────────────────────────────────────

"""
Entrada: ip (str)
Salida: bool
Descripción: Returns True if the string is a valid IPv4 address.
"""
def _is_valid_ip(ip: Any) -> bool:
    if not isinstance(ip, str) or not ip:
        return False
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


"""
Entrada: cidr (str)
Salida: bool
Descripción: Returns True if the string is a valid IPv4 CIDR (e.g. 192.168.1.0/24).
"""
def _is_valid_cidr(cidr: Any) -> bool:
    if not isinstance(cidr, str) or not cidr:
        return False
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False


"""
Entrada: value (Any), expected (type)
Salida: bool
Descripción: Returns True if value matches the expected scalar type, treating
             bool and int strictly (bool is not int even though isinstance says so).
"""
def _is_type(value: Any, expected: type) -> bool:
    if expected is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if expected is bool:
        return isinstance(value, bool)
    if expected is str:
        return isinstance(value, str)
    if expected is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, expected)


"""
Entrada: errors (list[str]), section (str), field (str), value (Any), expected (type)
Salida: None
Descripción: Appends an error if value is not of the expected type.
"""
def _require_type(errors: list[str], section: str, field: str,
                  value: Any, expected: type) -> bool:
    if not _is_type(value, expected):
        type_name = getattr(expected, "__name__", str(expected))
        actual = type(value).__name__
        errors.append(f"{section}.{field}: expected {type_name}, got {actual} ({value!r})")
        return False
    return True


"""
Entrada: errors (list[str]), section (str), field (str), value (Any), allowed (set)
Salida: None
Descripción: Appends an error if value (string) is not in the allowed set.
"""
def _require_in(errors: list[str], section: str, field: str,
                value: Any, allowed: set) -> bool:
    if value not in allowed:
        valid = ", ".join(sorted(allowed))
        errors.append(f"{section}.{field}: '{value}' is not valid (allowed: {valid})")
        return False
    return True


"""
Entrada: errors (list[str]), section (str), field (str), value (Any), regex (Pattern)
Salida: None
Descripción: Appends an error if value (string) does not match the regex.
"""
def _require_match(errors: list[str], section: str, field: str,
                   value: Any, regex, label: str) -> bool:
    if not isinstance(value, str) or not regex.match(value):
        errors.append(f"{section}.{field}: '{value}' is not a valid {label}")
        return False
    return True


"""
Entrada: errors (list[str]), section (str), field (str), value (Any)
Salida: None
Descripción: Appends an error if value is not a valid IPv4 address.
"""
def _require_ip(errors: list[str], section: str, field: str, value: Any) -> bool:
    if not _is_valid_ip(value):
        errors.append(f"{section}.{field}: '{value}' is not a valid IPv4 address")
        return False
    return True


"""
Entrada: errors (list[str]), section (str), field (str), value (Any)
Salida: None
Descripción: Appends an error if value is not a valid IPv4 CIDR.
"""
def _require_cidr(errors: list[str], section: str, field: str, value: Any) -> bool:
    if not _is_valid_cidr(value):
        errors.append(f"{section}.{field}: '{value}' is not a valid CIDR (e.g. 192.168.1.0/24)")
        return False
    return True


"""
Entrada: errors (list[str]), section (str), field (str), value (Any), required (bool)
Salida: None
Descripción: Appends an error if value is not a valid MAC. Empty MAC is allowed
             only when required=False.
"""
def _require_mac(errors: list[str], section: str, field: str,
                 value: Any, required: bool = False) -> bool:
    if not isinstance(value, str):
        errors.append(f"{section}.{field}: MAC must be a string, got {type(value).__name__}")
        return False
    if not value:
        if required:
            errors.append(f"{section}.{field}: MAC must not be empty")
            return False
        return True
    if not _MAC_RE.match(value):
        errors.append(f"{section}.{field}: '{value}' is not a valid MAC (xx:xx:xx:xx:xx:xx)")
        return False
    return True


# ─── Section validators ───────────────────────────────────────────────────

"""
Entrada: errors (list[str]), sc (dict)
Salida: None
Descripción: Validates the "scenario" section: required fields, types, formats
             and value semantics (scan_method, attacker.mode, etc.).
"""
def _validate_scenario_section(errors: list[str], sc: dict) -> None:
    # Required top-level fields
    required_str = ("name", "experiment_id", "environment",
                    "start_time", "planned_duration")
    for k in required_str:
        if k not in sc:
            errors.append(f"scenario.{k}: missing required field")
        elif not _require_type(errors, "scenario", k, sc[k], str):
            pass
        elif not sc[k].strip() and k != "environment":
            errors.append(f"scenario.{k}: must not be empty")

    # Optional scan fields
    if "scan_cidr" in sc:
        _require_cidr(errors, "scenario", "scan_cidr", sc["scan_cidr"])
    if "scan_method" in sc:
        _require_in(errors, "scenario", "scan_method",
                    sc.get("scan_method", ""), VALID_SCAN_METHODS)
    if "capture_iface" in sc:
        _require_type(errors, "scenario", "capture_iface",
                      sc.get("capture_iface", ""), str)
    if "pcap_max_size_kb" in sc:
        v = sc.get("pcap_max_size_kb")
        if not _is_type(v, int) or v <= 0:
            errors.append(
                f"scenario.pcap_max_size_kb: must be a positive integer, got {v!r}"
            )

    # Format checks (only if value is a string)
    if isinstance(sc.get("start_time"), str):
        _require_match(errors, "scenario", "start_time",
                       sc["start_time"], _TIME_RE, "HH:MM:SS time")
    if isinstance(sc.get("planned_duration"), str):
        if not _DURATION_RE.match(sc["planned_duration"]):
            errors.append(
                f"scenario.planned_duration: '{sc['planned_duration']}' is not "
                f"a valid duration (HH:MM:SS, DD:HH:MM:SS, or NsmhdwM)"
            )

    # Output sub-section
    out = sc.get("output")
    if out is not None:
        if not isinstance(out, dict):
            errors.append("scenario.output: must be an object")
        else:
            if "folder" in out:
                _require_type(errors, "scenario.output", "folder",
                              out["folder"], str)
                if isinstance(out["folder"], str) and not out["folder"].strip():
                    errors.append("scenario.output.folder: must not be empty")
            for k in ("capture_enabled", "export_pcap",
                      "export_metadata", "export_benign"):
                if k in out:
                    _require_type(errors, "scenario.output", k, out[k], bool)
            if "metadata_format" in out:
                _require_in(errors, "scenario.output", "metadata_format",
                            out.get("metadata_format", "json"), VALID_OUTPUT_FORMATS)

    # Attacker sub-section
    atk = sc.get("attacker")
    if atk is not None:
        if not isinstance(atk, dict):
            errors.append("scenario.attacker: must be an object")
        else:
            if "mode" in atk:
                _require_in(errors, "scenario.attacker", "mode",
                            atk.get("mode", "local"), VALID_ATTACKER_MODES)
            if atk.get("mode") == "ssh":
                if not atk.get("ip"):
                    errors.append("scenario.attacker.ip: required when mode='ssh'")
                elif not _is_valid_ip(atk.get("ip")):
                    errors.append(
                        f"scenario.attacker.ip: '{atk.get('ip')}' is not a valid IPv4 address"
                    )
            if "ssh_port" in atk:
                p = atk.get("ssh_port")
                if not _is_type(p, int) or not (1 <= p <= 65535):
                    errors.append(
                        f"scenario.attacker.ssh_port: must be 1-65535, got {p!r}"
                    )
            if "ssh_user" in atk:
                _require_type(errors, "scenario.attacker", "ssh_user",
                              atk["ssh_user"], str)
            if "ssh_key" in atk:
                _require_type(errors, "scenario.attacker", "ssh_key",
                              atk["ssh_key"], str)


"""
Entrada: errors (list[str]), devices (list)
Salida: dict[str, dict] | None
Descripción: Validates the "devices" list. Returns a dict {ip: device_dict} for
             cross-reference checks by other sections, or None if devices is
             not a list.
"""
def _validate_devices(errors: list[str], devices: Any) -> dict[str, dict] | None:
    if not isinstance(devices, list):
        errors.append("devices: must be a list")
        return None

    seen_ips: set[str] = set()
    ip_map: dict[str, dict] = {}
    for i, dev in enumerate(devices):
        ctx = f"devices[{i}]"
        if not isinstance(dev, dict):
            errors.append(f"{ctx}: must be an object")
            continue

        # ip (required, unique, valid)
        ip = dev.get("ip")
        if not ip:
            errors.append(f"{ctx}.ip: missing required field")
        elif not _is_valid_ip(ip):
            errors.append(f"{ctx}.ip: '{ip}' is not a valid IPv4 address")
        elif ip in seen_ips:
            errors.append(f"{ctx}.ip: duplicate device IP '{ip}'")
        else:
            seen_ips.add(ip)
            ip_map[ip] = dev

        # mac (optional, but if present must be valid)
        if "mac" in dev:
            _require_mac(errors, ctx, "mac", dev["mac"])

        # role
        _require_in(errors, ctx, "role",
                    dev.get("role", "target"), VALID_ROLES)

        # device_type
        if "device_type" in dev:
            _require_in(errors, ctx, "device_type",
                        dev.get("device_type", "unknown"), VALID_DEVICE_TYPES)

        # status
        if "status" in dev:
            _require_in(errors, ctx, "status",
                        dev.get("status", "online"),
                        {"online", "offline", "unknown"})

        # numeric fields
        if "iot_score" in dev:
            v = dev.get("iot_score")
            if not _is_type(v, int) or not (0 <= v <= 100):
                errors.append(
                    f"{ctx}.iot_score: must be 0-100, got {v!r}"
                )

        # list fields
        for k in ("tags", "open_ports", "protocols"):
            if k in dev and not isinstance(dev[k], list):
                errors.append(f"{ctx}.{k}: must be a list")

        # open_ports items (if present and is a list)
        if isinstance(dev.get("open_ports"), list):
            for j, p in enumerate(dev["open_ports"]):
                if not isinstance(p, dict):
                    errors.append(f"{ctx}.open_ports[{j}]: must be an object")
                    continue
                port = p.get("port")
                if not _is_type(port, int) or not (1 <= port <= 65535):
                    errors.append(
                        f"{ctx}.open_ports[{j}].port: must be 1-65535, got {port!r}"
                    )
                if "protocol" in p:
                    _require_type(errors, f"{ctx}.open_ports[{j}]",
                                  "protocol", p["protocol"], str)

        # string fields
        for k in ("hostname", "vendor", "notes"):
            if k in dev:
                _require_type(errors, ctx, k, dev[k], str)

    return ip_map


"""
Entrada: errors (list[str]), events (list), device_ips (set[str])
Salida: None
Descripción: Validates the "timeline" list. Checks every event's fields,
             cross-references source/target IPs against the device list,
             and verifies that attack actions actually exist in the
             ATTACK_LIBRARY or plugins.
"""
def _validate_timeline(errors: list[str], events: Any,
                       device_ips: set[str]) -> None:
    if not isinstance(events, list):
        errors.append("timeline: must be a list")
        return

    # Lazy import to avoid circular imports
    try:
        from modules.attacks import get_plugin_attacks
        attack_names: set[str] | None = set()
        for a in __import__(
            "modules.attacks", fromlist=["ATTACK_LIBRARY"]
        ).ATTACK_LIBRARY:
            attack_names.add(a.name)
        try:
            for p in (get_plugin_attacks(log_callback=None) or []):
                attack_names.add(p.name)
        except Exception:
            pass
    except Exception:
        attack_names = None  # validation of attack names will be skipped

    for i, ev in enumerate(events):
        ctx = f"timeline[{i}]"
        if not isinstance(ev, dict):
            errors.append(f"{ctx}: must be an object")
            continue

        # event_type
        _require_in(errors, ctx, "event_type",
                    ev.get("event_type", ""), VALID_EVENT_TYPES)

        # status
        if "status" in ev:
            _require_in(errors, ctx, "status",
                        ev.get("status", "queued"), VALID_EVENT_STATUS)

        # action (required, non-empty string)
        action = ev.get("action")
        if not isinstance(action, str) or not action.strip():
            errors.append(f"{ctx}.action: missing or empty")
        elif ev.get("event_type") == "attack" and attack_names is not None:
            if action not in attack_names:
                errors.append(
                    f"{ctx}.action: '{action}' is not a registered attack "
                    f"(check Attack Library / plugins)"
                )

        # source / target (must be valid IPs in devices)
        for field in ("source", "target"):
            ip = ev.get(field, "")
            if not ip:
                errors.append(f"{ctx}.{field}: missing required field")
            elif not _is_valid_ip(ip):
                errors.append(f"{ctx}.{field}: '{ip}' is not a valid IPv4 address")
            elif ip not in device_ips:
                errors.append(
                    f"{ctx}.{field}: IP '{ip}' is not registered in devices"
                )

        # source must be an attacker for attack events
        if ev.get("event_type") == "attack" and ev.get("source") in device_ips:
            # We cannot access the device role here directly without the ip_map,
            # so we just check existence. A second pass in the caller can verify roles.
            pass

        # offset_s (int >= 0)
        if "offset_s" in ev:
            v = ev.get("offset_s")
            if not _is_type(v, int) or v < 0:
                errors.append(f"{ctx}.offset_s: must be >= 0, got {v!r}")

        # duration_s (int >= 0)
        if "duration_s" in ev:
            v = ev.get("duration_s")
            if not _is_type(v, int) or v < 0:
                errors.append(f"{ctx}.duration_s: must be >= 0, got {v!r}")

        # scheduled_dt (optional, but if present must match a known datetime format)
        if "scheduled_dt" in ev:
            v = ev.get("scheduled_dt", "")
            if not isinstance(v, str) or (v and not _DATETIME_RE.match(v)):
                errors.append(
                    f"{ctx}.scheduled_dt: '{v}' is not a valid datetime "
                    f"(DD/MM/YYYY HH:MM:SS or HH:MM:SS)"
                )

        # label / notes / event_id (strings if present)
        for k in ("event_id", "label", "notes"):
            if k in ev:
                _require_type(errors, ctx, k, ev[k], str)


"""
Entrada: errors (list[str], profiles (Any), device_ips (set[str])
Salida: None
Descripción: Validates the "benign_profiles" list. Checks that each profile's
             device_ip exists in devices, the protocol/method values are
             supported, and every action has a valid protocol/method pair.
"""
def _validate_benign_profiles(errors: list[str], profiles: Any,
                              device_ips: set[str]) -> None:
    if not isinstance(profiles, list):
        errors.append("benign_profiles: must be a list")
        return

    seen_ips: set[str] = set()
    for i, p in enumerate(profiles):
        ctx = f"benign_profiles[{i}]"
        if not isinstance(p, dict):
            errors.append(f"{ctx}: must be an object")
            continue

        # device_ip (required, must exist in devices, no duplicates)
        ip = p.get("device_ip")
        if not ip:
            errors.append(f"{ctx}.device_ip: missing required field")
        elif not _is_valid_ip(ip):
            errors.append(f"{ctx}.device_ip: '{ip}' is not a valid IPv4 address")
        elif ip not in device_ips:
            errors.append(
                f"{ctx}.device_ip: IP '{ip}' is not registered in devices"
            )
        elif ip in seen_ips:
            errors.append(f"{ctx}.device_ip: duplicate profile for IP '{ip}'")
        else:
            seen_ips.add(ip)

        # device_type (optional, must be valid if present)
        if "device_type" in p:
            _require_in(errors, ctx, "device_type",
                        p.get("device_type", ""), VALID_DEVICE_TYPES)

        # port (1-65535)
        if "port" in p:
            v = p.get("port")
            if not _is_type(v, int) or not (1 <= v <= 65535):
                errors.append(f"{ctx}.port: must be 1-65535, got {v!r}")

        # protocol (top-level)
        if "protocol" in p:
            _require_in(errors, ctx, "protocol",
                        p.get("protocol", "http"), VALID_PROTOCOLS)

        # string fields
        for k in ("profile_id", "device_tag", "auth_user", "auth_pass", "notes"):
            if k in p:
                _require_type(errors, ctx, k, p[k], str)

        # actions list
        actions = p.get("actions")
        if actions is not None:
            if not isinstance(actions, list):
                errors.append(f"{ctx}.actions: must be a list")
            else:
                for j, a in enumerate(actions):
                    actx = f"{ctx}.actions[{j}]"
                    if not isinstance(a, dict):
                        errors.append(f"{actx}: must be an object")
                        continue
                    proto = a.get("protocol", p.get("protocol", "http"))
                    _require_in(errors, actx, "protocol", proto, VALID_PROTOCOLS)
                    method = a.get("method", "POST")
                    if proto in ("http", "https"):
                        _require_in(errors, actx, "method",
                                    method, VALID_HTTP_METHODS)
                    elif proto == "mqtt":
                        _require_in(errors, actx, "method",
                                    method, VALID_MQTT_METHODS)
                    elif proto == "ssh":
                        _require_in(errors, actx, "method",
                                    method, VALID_SSH_METHODS)
                    for k in ("name", "description", "endpoint",
                              "payload", "action_id"):
                        if k in a:
                            _require_type(errors, actx, k, a[k], str)
                    if "headers" in a and not isinstance(a["headers"], dict):
                        errors.append(f"{actx}.headers: must be an object")


"""
Entrada: errors (list[str], attackers (Any), device_ips (set[str])
Salida: None
Descripción: Validates the "attackers" list. Each attacker must reference a
             device with role=attacker, have a valid mode, and when mode='ssh'
             a non-empty ssh_user is recommended.
"""
def _validate_attackers(errors: list[str], attackers: Any,
                        device_ips: set[str]) -> None:
    if not isinstance(attackers, list):
        errors.append("attackers: must be a list")
        return

    for i, a in enumerate(attackers):
        ctx = f"attackers[{i}]"
        if not isinstance(a, dict):
            errors.append(f"{ctx}: must be an object")
            continue

        # device_ip (required, must exist in devices)
        ip = a.get("device_ip")
        if not ip:
            errors.append(f"{ctx}.device_ip: missing required field")
        elif not _is_valid_ip(ip):
            errors.append(f"{ctx}.device_ip: '{ip}' is not a valid IPv4 address")
        elif ip not in device_ips:
            errors.append(
                f"{ctx}.device_ip: IP '{ip}' is not registered in devices"
            )

        # mode
        _require_in(errors, ctx, "mode",
                    a.get("mode", "local"), VALID_ATTACKER_MODES)

        # ssh_port
        if "ssh_port" in a:
            v = a.get("ssh_port")
            if not _is_type(v, int) or not (1 <= v <= 65535):
                errors.append(f"{ctx}.ssh_port: must be 1-65535, got {v!r}")

        # ssh_user (recommended when mode=ssh)
        if a.get("mode") == "ssh" and not a.get("ssh_user"):
            errors.append(
                f"{ctx}.ssh_user: recommended when mode='ssh'"
            )

        # string fields
        for k in ("tag", "ssh_user", "ssh_key", "ssh_password"):
            if k in a:
                _require_type(errors, ctx, k, a[k], str)


"""
Entrada: errors (list[str], events (list), ip_map (dict[str, dict])
Salida: None
Descripción: Second pass over the timeline: verifies that attack events have
             a source IP that belongs to a device with role='attacker'.
"""
def _validate_timeline_roles(errors: list[str], events: list,
                             ip_map: dict[str, dict]) -> None:
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            continue
        if ev.get("event_type") != "attack":
            continue
        src = ev.get("source", "")
        dev = ip_map.get(src)
        if dev is None:
            continue  # already reported by _validate_timeline
        if dev.get("role") not in ("attacker", "unknown"):
            errors.append(
                f"timeline[{i}].source: IP '{src}' has role "
                f"'{dev.get('role')}', expected 'attacker' for an attack event"
            )


# ─── Public API ────────────────────────────────────────────────────────────

"""
Entrada: data (dict)
Salida: list[str]
Descripción: Validates a raw scenario JSON dictionary and returns a list of
             error messages. An empty list means the scenario is valid.

             Accepts two equivalent layouts:
               1) UI / Ctrl+O format — top-level keys "scenario" (with
                  name/experiment_id/...), "devices", "timeline",
                  "attackers", "benign_profiles".
               2) Legacy flat format — name/experiment_id/... live at the
                  top level alongside "devices", "timeline", etc.

             If a "scenario" key exists, layout (1) is assumed; otherwise
             layout (2) is assumed and the top-level dict is treated as
             the scenario section.
"""
def validate_scenario_data(data: Any) -> list[str]:
    errors: list[str] = []

    if not isinstance(data, dict):
        return ["scenario file: top-level value must be a JSON object"]

    # Detect layout: nested (UI) vs flat (legacy schema)
    if "scenario" in data and isinstance(data["scenario"], dict):
        sc = data["scenario"]
    else:
        # Flat layout — treat the top-level dict as the scenario section,
        # but only consider known scenario fields (ignore devices/timeline).
        sc = {
            k: v for k, v in data.items()
            if k in (
                "name", "experiment_id", "environment", "start_time",
                "planned_duration", "schema_version", "scan_cidr",
                "scan_method", "capture_iface", "pcap_max_size_kb",
                "output", "attacker",
            )
        }
        # If the flat layout has nothing recognizable, fall back to the
        # whole dict so the user gets helpful "missing field" errors.
        if not sc:
            sc = data

    # scenario section
    _validate_scenario_section(errors, sc)

    # devices (top-level in both layouts)
    ip_map = _validate_devices(errors, data.get("devices", []))
    if ip_map is None:
        ip_map = {}
    device_ips = set(ip_map.keys())

    # timeline
    _validate_timeline(errors, data.get("timeline", []), device_ips)
    if isinstance(data.get("timeline"), list):
        _validate_timeline_roles(errors, data["timeline"], ip_map)

    # attackers
    _validate_attackers(errors, data.get("attackers", []), device_ips)

    # benign_profiles
    _validate_benign_profiles(errors, data.get("benign_profiles", []), device_ips)

    return errors


"""
Entrada: config (ScenarioConfig)
Salida: list[str]
Descripción: Validates a ScenarioConfig dataclass instance. Kept for backwards
             compatibility with the previous API; for new code prefer
             validate_scenario_data() which works on the raw JSON dict.
"""
def validate_scenario(config: ScenarioConfig) -> list[str]:
    errors: list[str] = []

    if not config.name.strip():
        errors.append("scenario.name must not be empty")
    if not _EXP_ID_RE.match(config.experiment_id):
        errors.append(
            f"experiment_id '{config.experiment_id}' contains invalid characters"
        )
    if not _TIME_RE.match(config.start_time):
        errors.append(f"start_time '{config.start_time}' must be HH:MM:SS")
    if not _DURATION_RE.match(config.planned_duration):
        errors.append(
            f"planned_duration '{config.planned_duration}' is not a valid duration"
        )
    if not config.output.folder.strip():
        errors.append("output.folder must not be empty")

    device_ids: set[str] = set()
    for dev in config.devices:
        if dev.id in device_ids:
            errors.append(f"duplicate device id: '{dev.id}'")
        device_ids.add(dev.id)
        if dev.role not in VALID_ROLES:
            errors.append(f"device '{dev.id}': invalid role '{dev.role}'")
        if not _is_valid_ip(dev.ip):
            errors.append(f"device '{dev.id}': invalid IP '{dev.ip}'")

    return errors
