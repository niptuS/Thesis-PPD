import logging
from modules.interfaces.interface_lister import InterfaceInfo, list_interfaces

logger = logging.getLogger(__name__)

_WIRED_PREFIXES:    tuple[str, ...] = ("eth", "en", "eno", "enp", "ens")
_WIRELESS_PREFIXES: tuple[str, ...] = ("wlan", "wlp", "wl", "wifi", "wlo")


def _score(iface: InterfaceInfo) -> int:
    score = 0
    if iface.is_up:        score += 40
    if iface.is_private:   score += 30
    if not iface.is_virtual: score += 20
    name_lower = iface.name.lower()
    if any(name_lower.startswith(p) for p in _WIRED_PREFIXES):    score += 10
    elif any(name_lower.startswith(p) for p in _WIRELESS_PREFIXES): score += 5
    if iface.speed_mbps > 0: score += min(iface.speed_mbps // 100, 5)
    return score


def select_default_interface(
    interfaces: list[InterfaceInfo] | None = None,
) -> InterfaceInfo | None:
    candidates = interfaces if interfaces is not None else list_interfaces()
    if not candidates:
        logger.warning("no network interfaces available")
        return None

    ranked = sorted(candidates, key=_score, reverse=True)
    selected = ranked[0]
    logger.info(
        "default interface selected: %s (%s) score=%d",
        selected.name, selected.ip, _score(selected),
    )
    return selected


def filter_by_state(
    interfaces: list[InterfaceInfo],
    up_only: bool = True,
) -> list[InterfaceInfo]:
    return [i for i in interfaces if i.is_up] if up_only else interfaces


def filter_private_only(interfaces: list[InterfaceInfo]) -> list[InterfaceInfo]:
    return [i for i in interfaces if i.is_private]