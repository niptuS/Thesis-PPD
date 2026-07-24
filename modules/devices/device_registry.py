import json
import logging
from pathlib import Path

from modules.devices.device_schema import DeviceEntry

logger = logging.getLogger(__name__)

_DEFAULT_REGISTRY_PATH = Path("saves/devices/registry.json")


class DeviceRegistry:

    """
    Entrada: path (Path)
    Salida: None
    Descripción: Initializes the device registry bound to a JSON file path.
    """
    def __init__(self, path: Path = _DEFAULT_REGISTRY_PATH) -> None:
        self._path: Path = path
        self._devices: dict[str, DeviceEntry] = {}

    """
    Entrada: device (DeviceEntry)
    Salida: None
    Descripción: Adds a new device, raising if its IP is already registered.
    """
    def add(self, device: DeviceEntry) -> None:
        if device.ip in self._devices:
            raise KeyError(f"device {device.ip!r} already registered")
        self._devices[device.ip] = device
        logger.info("device added: %s", device.ip)

    """
    Entrada: device (DeviceEntry)
    Salida: None
    Descripción: Updates an existing device, raising if its IP is not registered.
    """
    def update(self, device: DeviceEntry) -> None:
        if device.ip not in self._devices:
            raise KeyError(f"device {device.ip!r} not found")
        self._devices[device.ip] = device
        logger.info("device updated: %s", device.ip)

    """
    Entrada: device (DeviceEntry)
    Salida: None
    Descripción: Inserts or replaces a device by IP.
    """
    def upsert(self, device: DeviceEntry) -> None:
        self._devices[device.ip] = device

    """
    Entrada: ip (str)
    Salida: None
    Descripción: Removes a device by IP, raising if not found.
    """
    def remove(self, ip: str) -> None:
        if ip not in self._devices:
            raise KeyError(f"device {ip!r} not found")
        del self._devices[ip]
        logger.info("device removed: %s", ip)

    """
    Entrada: ip (str)
    Salida: DeviceEntry
    Descripción: Returns the device with the given IP, raising if not found.
    """
    def get(self, ip: str) -> DeviceEntry:
        if ip not in self._devices:
            raise KeyError(f"device {ip!r} not found")
        return self._devices[ip]

    """
    Entrada: None
    Salida: list[DeviceEntry]
    Descripción: Returns all registered devices.
    """
    def all(self) -> list[DeviceEntry]:
        return list(self._devices.values())

    """
    Entrada: tag (str)
    Salida: list[DeviceEntry]
    Descripción: Returns devices matching the given tag.
    """
    def filter_by_tag(self, tag: str) -> list[DeviceEntry]:
        return [d for d in self._devices.values() if tag in d.tags]

    """
    Entrada: min_score (int)
    Salida: list[DeviceEntry]
    Descripción: Returns devices whose IoT score is at least min_score.
    """
    def filter_by_min_score(self, min_score: int) -> list[DeviceEntry]:
        return [d for d in self._devices.values() if d.iot_score >= min_score]

    """
    Entrada: None
    Salida: None
    Descripción: Removes all registered devices.
    """
    def clear(self) -> None:
        self._devices.clear()

    """
    Entrada: path (Path | None)
    Salida: None
    Descripción: Saves the registry to JSON, using atomic replace.
    """
    def save(self, path: Path | None = None) -> None:
        target = path or self._path
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = [d.to_dict() for d in self._devices.values()]
        tmp = target.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(target)
        except OSError as exc:
            logger.error("failed to save registry to %s: %s", target, exc)
            raise
        logger.info("registry saved: %s (%d devices)", target, len(payload))

    """
    Entrada: path (Path | None)
    Salida: None
    Descripción: Loads the registry from a JSON file, replacing current devices.
    """
    def load(self, path: Path | None = None) -> None:
        source = path or self._path
        if not source.exists():
            raise FileNotFoundError(f"registry file not found: {source}")
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed registry file {source}: {exc}") from exc

        self._devices.clear()
        for entry in raw:
            dev = DeviceEntry.from_dict(entry)
            self._devices[dev.ip] = dev
        logger.info("registry loaded: %s (%d devices)", source, len(self._devices))

    """
    Entrada: None
    Salida: int
    Descripción: Returns the number of registered devices.
    """
    def __len__(self) -> int:
        return len(self._devices)

    """
    Entrada: ip (str)
    Salida: bool
    Descripción: Returns True if a device with the given IP is registered.
    """
    def __contains__(self, ip: str) -> bool:
        return ip in self._devices
