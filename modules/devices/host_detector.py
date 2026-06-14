"""Detect the host machine's IP and MAC for auto-registration as attacker."""
import socket
import uuid
import logging

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

logger = logging.getLogger(__name__)


def get_host_ip(iface_name: str = "") -> str:
    """Detect the host machine's primary IPv4 address."""
    try:
        if iface_name and _HAS_PSUTIL:
            addrs = psutil.net_if_addrs().get(iface_name, [])
            for a in addrs:
                if a.family.name == "AF_INET":
                    return a.address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except (OSError, socket.error, AttributeError) as exc:
        logger.warning("Cannot detect host IP: %s", exc)
        return "127.0.0.1"


def get_host_mac() -> str:
    """Get the host machine's MAC address."""
    try:
        mac_int = uuid.getnode()
        mac = ":".join(
            f"{(mac_int >> (8 * (5 - i))) & 0xFF:02x}"
            for i in range(6)
        )
        return mac
    except (ValueError, TypeError) as exc:
        logger.warning("Cannot detect host MAC: %s", exc)
        return "00:00:00:00:00:00"


def get_host_hostname() -> str:
    """Get the host machine's hostname."""
    try:
        return socket.gethostname()
    except (OSError, socket.error) as exc:
        logger.warning("Cannot detect hostname: %s", exc)
        return "localhost"
