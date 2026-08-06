"""
DevicesController — Three-zone navigation:
  Zone 1: Settings fields (Interface, CIDR, Method)
  Zone 2: Device table (scroll with ►)
  Zone 3: Device detail fields (navigate + inline edit)
"""
from __future__ import annotations
import curses
import threading
import time
from datetime import datetime
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from design.Menu import MenuApp

from design.Menu_logs import EVENT_LOG
from design.Menu_devices import PAGE_SIZE, DEVICE_ROLES
from modules.devices.device_schema import DeviceEntry
from modules.devices.device_registry import DeviceRegistry
from modules.devices.scanner import scan_network, merge_by_mac, SCAN_METHODS, _enrich_vendor_tags, _apply_fingerprint
from modules.devices.fingerprint import get_type_label
from modules.devices.host_detector import get_host_ip, get_host_mac, get_host_hostname
from design.overlays import (
    role_select_overlay, method_select_overlay,
    text_input_overlay,
)

DETAIL_FIELDS = [
    ("role", "Role", "select"),
    ("tags", "Tags", "text"),
    ("hostname", "Hostname", "text"),
    ("notes", "Notes", "text"),
    ("device_type", "Device type", "readonly"),
]


class DevicesController:
    """
    Entrada: app
    Salida: None
    Descripción: init
    """
    def __init__(self, app: "MenuApp") -> None:
        self._app = app
        self._registry = DeviceRegistry()
        self._scan_thread: Optional[threading.Thread] = None
        self._scan_cancel = threading.Event()
        self._device_cursor: int = 0
        self._page: int = 0
        self._zone: str = "settings"
        self._detail_cursor: int = 0
        self._host_added: bool = False

    """
    Entrada: None
    Salida: None
    Descripción: devices
    """
    @property
    def devices(self) -> list[DeviceEntry]:
        return self._registry.all()

    """
    Entrada: None
    Salida: int
    Descripción: device cursor
    """
    @property
    def device_cursor(self) -> int:
        return self._device_cursor

    """
    Entrada: None
    Salida: int
    Descripción: page
    """
    @property
    def page(self) -> int:
        return self._page

    """
    Entrada: None
    Salida: int
    Descripción: detail cursor
    """
    @property
    def detail_cursor(self) -> int:
        return self._detail_cursor if self._zone == "detail" else -1

    """
    Entrada: None
    Salida: DeviceRegistry
    Descripción: registry
    """
    @property
    def registry(self) -> DeviceRegistry:
        return self._registry

    """
    Entrada: None
    Salida: None
    Descripción: selected device
    """
    def _selected_device(self) -> Optional[DeviceEntry]:
        devs = self.devices
        if devs and 0 <= self._device_cursor < len(devs):
            return devs[self._device_cursor]
        return None

    """
    Entrada: iface
    Salida: None
    Descripción: ensure host attacker
    """
    def ensure_host_attacker(self, iface: str = "") -> None:
        if self._host_added:
            return
        ip = get_host_ip(iface)
        mac = get_host_mac()
        hostname = get_host_hostname()
        if ip in self._registry:
            existing = self._registry.get(ip)
            existing.role = "attacker"
        else:
            dev = DeviceEntry(ip=ip, mac=mac, hostname=hostname,
                              role="attacker", device_type="attacker",
                              status="online", tags=["host", "attacker"])
            self._registry.upsert(dev)
        EVENT_LOG.info(f"Host registered as attacker: {ip} ({hostname})")
        self._host_added = True
        self._refresh()

    """
    Entrada: None
    Salida: None
    Descripción: Update host device IP to current value after loading saved config.
    """
    def update_host_ip(self) -> None:
        current_ip = get_host_ip()
        current_mac = get_host_mac()
        hostname = get_host_hostname()
        for dev in self._registry.all():
            if "host" in dev.tags and dev.role == "attacker":
                if dev.ip != current_ip:
                    old_ip = dev.ip
                    try:
                        self._registry.remove(old_ip)
                    except KeyError:
                        pass
                    dev.ip = current_ip
                    dev.mac = current_mac
                    dev.hostname = hostname
                    self._registry.upsert(dev)
                    EVENT_LOG.info(
                        f"Host IP updated: {old_ip} → {current_ip}"
                    )
                    self._refresh()
                return
        self._host_added = False
        self.ensure_host_attacker()

    """
    Entrada: key
    Salida: bool
    Descripción: handle key
    """
    def handle_key(self, key: int) -> bool:
        action_map = {
            ord("s"): self._do_scan, ord("S"): self._do_scan,
            ord("a"): self._do_add_manual, ord("A"): self._do_add_manual,
            ord("r"): self._do_remove, ord("R"): self._do_remove,
            ord("m"): self._do_change_method, ord("M"): self._do_change_method,
            ord("c"): self._do_set_cidr, ord("C"): self._do_set_cidr,
            14: self._app._do_iface_select,
            24: self._do_cancel_scan,
        }
        action = action_map.get(key)
        if action is not None:
            action()
            return True

        if self._zone == "settings":
            if key == curses.KEY_DOWN:
                section = self._app._section()
                n_fields = len(section.field_map) if section.field_map else 0
                if n_fields > 0 and self._app.field_cursor >= n_fields - 1 and self.devices:
                    self._zone = "table"
                    self._app.field_cursor = 99
                    self._device_cursor = 0
                    self._sync_page()
                    self._refresh()
                    return True
                return False
            return False

        if self._zone == "table":
            if key == curses.KEY_DOWN:
                devs = self.devices
                if devs and self._device_cursor < len(devs) - 1:
                    self._device_cursor += 1
                    self._sync_page()
                    self._refresh()
                elif devs and self._selected_device():
                    self._zone = "detail"
                    self._detail_cursor = 0
                    self._refresh()
                return True
            if key == curses.KEY_UP:
                if self._device_cursor > 0:
                    self._device_cursor -= 1
                    self._sync_page()
                    self._refresh()
                else:
                    self._zone = "settings"
                    section = self._app._section()
                    n_fields = len(section.field_map) if section.field_map else 0
                    self._app.field_cursor = max(0, n_fields - 1)
                    self._refresh()
                return True
            if key in (curses.KEY_ENTER, 10, 13):
                if self._selected_device():
                    self._zone = "detail"
                    self._detail_cursor = 0
                    self._refresh()
                return True
            if key == curses.KEY_NPAGE:
                devs = self.devices
                if devs:
                    tp = max(1, (len(devs) + PAGE_SIZE - 1) // PAGE_SIZE)
                    if self._page < tp - 1:
                        self._page += 1
                        self._device_cursor = self._page * PAGE_SIZE
                        self._refresh()
                return True
            if key == curses.KEY_PPAGE:
                if self.devices and self._page > 0:
                    self._page -= 1
                    self._device_cursor = self._page * PAGE_SIZE
                    self._refresh()
                return True
            return True

        if self._zone == "detail":
            if key == curses.KEY_DOWN:
                if self._detail_cursor < len(DETAIL_FIELDS) - 1:
                    self._detail_cursor += 1
                    self._refresh()
                return True
            if key == curses.KEY_UP:
                if self._detail_cursor > 0:
                    self._detail_cursor -= 1
                    self._refresh()
                else:
                    self._zone = "table"
                    self._detail_cursor = -1
                    self._refresh()
                return True
            if key in (curses.KEY_ENTER, 10, 13):
                self._edit_detail_field()
                return True
            if key in (27, curses.KEY_LEFT):
                self._zone = "table"
                self._detail_cursor = -1
                self._refresh()
                return True
            return True

        return False

    """
    Entrada: None
    Salida: None
    Descripción: sync page
    """
    def _sync_page(self):
        self._page = self._device_cursor // PAGE_SIZE

    """
    Entrada: None
    Salida: None
    Descripción: clamp cursor
    """
    def _clamp_cursor(self):
        total = len(self.devices)
        if total == 0:
            self._device_cursor = 0
            self._page = 0
            self._zone = "settings"
        else:
            self._device_cursor = min(self._device_cursor, total - 1)
            self._sync_page()

    """
    Entrada: None
    Salida: None
    Descripción: refresh
    """
    def _refresh(self):
        if self._zone in ("table", "detail"):
            self._app.field_cursor = 99
        self._app._refresh_devices_section()

    """
    Entrada: None
    Salida: None
    Descripción: edit detail field
    """
    def _edit_detail_field(self):
        device = self._selected_device()
        if device is None:
            return
        if self._app._stdscr is None:
            return
        stdscr = self._app._stdscr

        attr, label, ftype = DETAIL_FIELDS[self._detail_cursor]

        if ftype == "readonly":
            EVENT_LOG.warn(f"{label} is read-only (set by fingerprinting)")
            return

        if ftype == "select" and attr == "role":
            new = role_select_overlay(stdscr, device.role, DEVICE_ROLES)
            if new != device.role:
                device.role = new
                EVENT_LOG.info(f"Role of {device.ip} → {new}")

        elif ftype == "text":
            current = getattr(device, attr, "")
            if isinstance(current, list):
                current = " ".join(current)
            new = text_input_overlay(stdscr, f"Edit {label}", str(current))
            if new is not None and new != str(current):
                if attr == "tags":
                    device.tags = [t.strip() for t in new.split() if t.strip()]
                else:
                    setattr(device, attr, new)
                EVENT_LOG.info(f"{label} of {device.ip} → {new}")

        self._refresh()

    """
    Entrada: None
    Salida: None
    Descripción: do add manual
    """
    def _do_add_manual(self):
        if self._app._stdscr is None:
            return
        stdscr = self._app._stdscr
        ip = text_input_overlay(stdscr, "Device IP")
        if ip is None or not ip.strip():
            return
        ip = ip.strip()

        # Validate IP format before proceeding
        import ipaddress as _ipaddr
        try:
            _ipaddr.IPv4Address(ip)
        except ValueError:
            EVENT_LOG.error(f"Invalid IP address: '{ip}' — must be a valid IPv4 (e.g. 192.168.1.10)")
            return

        if ip in self._registry:
            EVENT_LOG.warn(f"Device {ip} already exists")
            return
        mac = text_input_overlay(stdscr, "MAC Address (optional)", "") or ""
        mac = mac.strip()

        # Validate MAC format if provided
        if mac:
            import re as _re
            if not _re.match(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", mac):
                EVENT_LOG.error(f"Invalid MAC address: '{mac}' — format must be XX:XX:XX:XX:XX:XX")
                return

        from design.Menu import choice_select_overlay
        role = choice_select_overlay(stdscr, "Role", DEVICE_ROLES, "target")
        try:
            dev = DeviceEntry(ip=ip, mac=mac, role=role or "target", status="online")
            dev = _enrich_vendor_tags(dev)
            dev = _apply_fingerprint(dev)
            self._registry.upsert(dev)
            self._device_cursor = len(self.devices) - 1
            self._zone = "table"
            self._sync_page()
            EVENT_LOG.ok(f"Device added manually: {ip} ({role})")
        except ValueError as exc:
            EVENT_LOG.error(f"Could not add device: {exc}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            EVENT_LOG.error(f"Unexpected error adding device: {exc}")
        self._refresh()


    """
    Entrada: None
    Salida: None
    Descripción: do scan
    """
    def _do_scan(self):
        if self._scan_thread is not None and self._scan_thread.is_alive():
            EVENT_LOG.warn("A scan is already in progress")
            return
        from design.Menu import CAPTURE_IFACE
        iface = CAPTURE_IFACE
        cidr = getattr(self._app.active_config, "scan_cidr", "192.168.1.0/24")
        method = getattr(self._app.active_config, "scan_method", "nmap")
        if not iface or not any(c.isalnum() for c in iface):
            EVENT_LOG.error("Select an interface first (Ctrl+N)")
            return
        self.ensure_host_attacker(iface)
        EVENT_LOG.info(f"Scan started — {method} {cidr} on {iface}")
        self._scan_cancel.clear()
        self._scan_thread = threading.Thread(target=self._scan_worker, args=(method, cidr, iface), daemon=True)
        self._scan_thread.start()

    """
    Entrada: method, cidr, iface
    Salida: None
    Descripción: scan worker
    """
    def _scan_worker(self, method, cidr, iface):
        start = time.time()
        try:
            new_devices = scan_network(iface_name=iface, cidr=cidr, method=method)
        except Exception as exc:
            EVENT_LOG.error(f"Scan error: {exc}")
            return
        if self._scan_cancel.is_set():
            EVENT_LOG.warn("Scan aborted")
            return
        elapsed = round(time.time() - start, 1)
        merged = merge_by_mac(self._registry.all(), new_devices)
        self._registry.clear()
        for d in merged:
            self._registry.upsert(d)
        self._app._last_scan_time = datetime.now().strftime("%H:%M:%S")
        for dev in new_devices:
            EVENT_LOG.info(f"  {dev.ip:<16} {get_type_label(dev.device_type)}  vendor={dev.vendor}")
        EVENT_LOG.ok(f"Scan: {len(merged)} devices ({elapsed}s)")
        if self._zone == "settings" and self.devices:
            self._zone = "table"
            self._app.field_cursor = 99
            self._device_cursor = 0
            self._page = 0
        self._refresh()

    """
    Entrada: None
    Salida: None
    Descripción: do cancel scan
    """
    def _do_cancel_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_cancel.set()
            EVENT_LOG.warn("Canceling scan…")

    """
    Entrada: None
    Salida: None
    Descripción: do remove
    """
    def _do_remove(self):
        device = self._selected_device()
        if device is None:
            return
        ip = device.ip
        try:
            self._registry.remove(ip)
        except KeyError:
            pass
        ctrl_bp = getattr(self._app, "_ctrl_benign", None)
        if ctrl_bp:
            ctrl_bp._profiles = [p for p in ctrl_bp._profiles if p.device_ip != ip]
            ctrl_bp._clamp_cursor()
        ctrl_atk = getattr(self._app, "_ctrl_attackers", None)
        if ctrl_atk and ip in ctrl_atk._profiles:
            del ctrl_atk._profiles[ip]
        ctrl_tl = getattr(self._app, "_ctrl_timeline", None)
        if ctrl_tl:
            ctrl_tl._manager._events = [
                e for e in ctrl_tl._manager._events
                if ip not in (e.source, e.target)
            ]
            ctrl_tl._clamp_cursor()
        EVENT_LOG.info(f"Device removed (+ cascade): {ip}")
        if self._zone == "detail":
            self._zone = "table"
        self._clamp_cursor()
        self._refresh()

    """
    Entrada: None
    Salida: None
    Descripción: do change method
    """
    def _do_change_method(self):
        if self._app._stdscr is None:
            return
        current = getattr(self._app.active_config, "scan_method", "nmap")
        selected = method_select_overlay(self._app._stdscr, current, SCAN_METHODS)
        if selected != current and self._app.active_config:
            self._app.active_config.scan_method = selected
            EVENT_LOG.info(f"Scan method: {selected}")
            self._refresh()

    """
    Entrada: None
    Salida: None
    Descripción: do set cidr
    """
    def _do_set_cidr(self):
        self._zone = "settings"
        section = self._app._section()
        for i, field in enumerate(section.field_map):
            if field.attr_path == "scan_cidr":
                self._app.field_cursor = i
                self._app._start_inline(field)
                return
