"""
Entrada: None
Salida: EventExecutor class
Descripción: Event executor — fires timeline events (benign and attack) by
             routing them through the unified communication layer (HTTP, MQTT,
             SSH, Local). Extracted from the former LiveExecutionEngine
             monolith so that event-dispatch decisions can be tested
             independently of capture and flow extraction.
"""
from __future__ import annotations

import importlib
import threading
import time
import logging
from typing import Callable, Optional

from modules.comms import (
    LocalChannel, HTTPChannel, MQTTChannel, SSHChannel,
)

logger = logging.getLogger(__name__)


class EventExecutor:
    """
    Entrada: log_fn (Callable[[str, str], None] | None)
    Salida: None
    Descripción: Initializes the event executor with an optional logger
                 callback. Channels and profiles are registered later via
                 register_*() methods before fire() is called.
    """

    def __init__(self, log_fn: Optional[Callable[[str, str], None]] = None) -> None:
        self._log_fn = log_fn
        self._http = HTTPChannel(timeout=10)
        self._profiles: list = []
        self._device_map: dict[str, str] = {}
        self._attacker_profiles: dict = {}
        self._get_executor: Optional[Callable[[str], Optional[SSHChannel]]] = None
        self._ssh_executor: Optional[SSHChannel] = None
        self._local = LocalChannel()
        # Callbacks for clearing the active-event label after duration_s seconds
        self._on_benign_complete: Optional[Callable[[str], None]] = None
        self._on_attack_complete: Optional[Callable[[str], None]] = None
        # Labels shown in the Live panel
        self.active_benign: str = "—"
        self.active_attack: str = "—"

    # ── Configuration ────────────────────────────────────────────────────────

    """
    Entrada: profiles (list)
    Salida: None
    Descripción: Sets the benign profiles used to look up device actions.
    """
    def set_profiles(self, profiles: list) -> None:
        self._profiles = profiles or []

    """
    Entrada: device_map (dict[str, str])
    Salida: None
    Descripción: Sets the {ip: role} map used to find the gateway (first
                 benign device) for attack commands.
    """
    def set_device_map(self, device_map: dict) -> None:
        self._device_map = dict(device_map or {})

    """
    Entrada: profiles (dict)
    Salida: None
    Descripción: Sets the {ip: AttackerProfile} map used to pick the right
                 SSH executor for each attack.
    """
    def set_attacker_profiles(self, profiles: dict) -> None:
        self._attacker_profiles = dict(profiles or {})

    """
    Entrada: getter (Callable[[str], SSHChannel | None])
    Salida: None
    Descripción: Sets the callback used to obtain an SSHChannel for a given
                 attacker IP (typically AttackersController.get_executor).
    """
    def set_executor_getter(self, getter: Callable[[str], Optional[SSHChannel]]) -> None:
        self._get_executor = getter

    """
    Entrada: executor (SSHChannel | None)
    Salida: None
    Descripción: Sets the fallback SSH executor used when no per-attacker
                 executor is registered (legacy single-attacker mode).
    """
    def set_ssh_executor(self, executor: Optional[SSHChannel]) -> None:
        self._ssh_executor = executor

    """
    Entrada: on_benign_complete (Callable[[str], None]), on_attack_complete (Callable[[str], None])
    Salida: None
    Descripción: Sets callbacks invoked when a time-boxed event completes
                 (after its duration_s). The label of the completed event is
                 passed as the argument.
    """
    def set_complete_callbacks(
        self,
        on_benign_complete: Optional[Callable[[str], None]] = None,
        on_attack_complete: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._on_benign_complete = on_benign_complete
        self._on_attack_complete = on_attack_complete

    # ── Firing events ───────────────────────────────────────────────────────

    """
    Entrada: ev (dict)
    Salida: None
    Descripción: Fire a single timeline event — route to the benign or attack
                 executor and schedule a clearer thread for time-boxed events.
    """
    def fire(self, ev: dict) -> None:
        ev_type = ev.get("event_type", ev.get("type", "unknown"))
        action = ev.get("action", "")
        target = ev.get("target", "")
        source = ev.get("source", "")
        label = ev.get("label", action)
        duration_s = ev.get("duration_s", 0)

        self._log(f"Event: {label}  {source}→{target}", "INFO")

        if ev_type == "benign":
            self.active_benign = label
            self._exec_benign(action, target, duration_s)
        elif ev_type in ("attack", "malicious"):
            self.active_attack = label
            self._exec_attack(action, target, duration_s, source_ip=source)

        if duration_s > 0:
            self._schedule_clearer(ev_type, label, duration_s)

    """
    Entrada: ev_type (str), label (str), duration_s (int)
    Salida: None
    Descripción: Schedule a background thread that waits duration_s seconds
                 and then clears the active-event label and invokes the
                 completion callback.
    """
    def _schedule_clearer(self, ev_type: str, label: str, duration_s: int) -> None:
        def _clear_after():
            time.sleep(duration_s)
            if ev_type == "benign":
                self.active_benign = "—"
                if self._on_benign_complete:
                    self._on_benign_complete(label)
            elif ev_type in ("attack", "malicious"):
                self.active_attack = "—"
                if self._on_attack_complete:
                    self._on_attack_complete(label)
            self._log(f"Event completed: {label}", "INFO")
        threading.Thread(target=_clear_after, daemon=True).start()

    # ── Benign events ──────────────────────────────────────────────────────

    """
    Entrada: action_name (str), target_ip (str), duration_s (int)
    Salida: None
    Descripción: Find the benign profile for the target device and execute
                 the action via the matching channel in a background thread.
    """
    def _exec_benign(self, action_name: str, target_ip: str, duration_s: int) -> None:
        profile = None
        for p in self._profiles:
            if p.device_ip == target_ip:
                profile = p
                break
        if profile is None:
            self._log(f"No benign profile for {target_ip} — event only logged", "WARN")
            return

        action = profile.get_action(action_name)
        if action is None:
            self._log(f"Action '{action_name}' not found in profile of {target_ip}", "WARN")
            return

        def _run():
            try:
                if action.protocol in ("http", "https"):
                    result = self._http.execute(
                        target_ip=target_ip,
                        command=action_name,
                        port=profile.port,
                        method=action.method,
                        endpoint=action.endpoint,
                        payload=action.payload,
                    )
                    if result.success:
                        self._log(f"IoT OK: {action_name} → {target_ip} ({result.duration:.1f}s)", "OK")
                    else:
                        self._log(f"IoT error: {action_name} → {target_ip}: {result.error}", "ERROR")
                elif action.protocol == "mqtt":
                    try:
                        mqtt_port = 1883
                        if profile.port in (1883, 8883):
                            mqtt_port = profile.port
                        mqtt = MQTTChannel(
                            broker_host=target_ip,
                            broker_port=mqtt_port,
                        )
                        result = mqtt.send_action(action, action.payload)
                        if result.success:
                            self._log(f"MQTT OK: {action_name} topic={action.endpoint}", "OK")
                        else:
                            self._log(f"MQTT error: {result.error}", "ERROR")
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        self._log(f"MQTT unavailable: {e}", "ERROR")
                else:
                    self._log(f"Protocol '{action.protocol}' not supported for {action_name}", "WARN")
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._log(f"Error executing {action_name}: {e}", "ERROR")

        threading.Thread(target=_run, daemon=True).start()

    # ── Attack events ──────────────────────────────────────────────────────

    """
    Entrada: source_ip (str), need_ssh (bool)
    Salida: attacker profile or None
    Descripción: Find the best attacker profile for the given source IP,
                 preferring SSH-capable profiles with credentials.
    """
    def _find_attacker_profile(self, source_ip: str, need_ssh: bool = False):
        if source_ip and source_ip in self._attacker_profiles:
            return self._attacker_profiles[source_ip]
        for p in self._attacker_profiles.values():
            if need_ssh and p.mode == "ssh" and p.has_credentials:
                return p
        for p in self._attacker_profiles.values():
            if p.mode == "ssh":
                return p
        for p in self._attacker_profiles.values():
            return p
        return None

    """
    Entrada: attack_name (str), target_ip (str), duration_s (int), source_ip (str)
    Salida: None
    Descripción: Execute an attack by routing to the correct attacker (local,
                 SSH, or plugin fallback); sudo is handled by the channel.
    """
    def _exec_attack(self, attack_name: str, target_ip: str,
                     duration_s: int, source_ip: str = "") -> None:
        from modules.attacks import get_attack_class, get_plugin_attacks
        attack_def = get_attack_class(attack_name)
        if attack_def is None:
            plugins = get_plugin_attacks() or []
            for p in plugins:
                if p.name == attack_name:
                    attack_def = p
                    break
        if attack_def is None:
            self._log(f"Attack '{attack_name}' not found", "ERROR")
            return

        gateway = ""
        for ip, role in self._device_map.items():
            if role == "benign":
                gateway = ip
                break

        cmd = attack_def.build_command(
            target_ip=target_ip, duration=duration_s or 30, port=80, gateway=gateway,
        )
        needs_root = attack_def.requires_root

        profile = self._find_attacker_profile(source_ip, need_ssh=True)
        mode = profile.mode if profile else "local"
        label = profile.tag or profile.device_ip if profile else "local"
        self._log(f"Executor: {label} ({mode}) root={'yes' if needs_root else 'no'}", "INFO")
        self._log(f"[{attack_def.tool}] {cmd[:80]}", "INFO")

        if hasattr(attack_def, "local_fallback") and attack_def.local_fallback:
            self._exec_plugin(attack_def, target_ip, duration_s)
            return

        if profile and mode == "ssh" and profile.has_credentials:
            self._exec_attack_ssh(attack_name, cmd, target_ip,
                                  source_ip=profile.device_ip, use_sudo=needs_root)
        else:
            self._exec_attack_local(attack_name, cmd, target_ip, duration_s, needs_root)

    """
    Entrada: name (str), cmd (str), target_ip (str), source_ip (str), use_sudo (bool)
    Salida: None
    Descripción: Run an attack command on a remote attacker via SSH, dispatching
                 to the matching channel in a background thread.
    """
    def _exec_attack_ssh(self, name: str, cmd: str, target_ip: str,
                         source_ip: str = "", use_sudo: bool = False) -> None:
        executor = None
        if self._get_executor and source_ip:
            executor = self._get_executor(source_ip)
        if executor is None and self._get_executor:
            for p in self._attacker_profiles.values():
                if p.mode == "ssh" and p.has_credentials:
                    executor = self._get_executor(p.device_ip)
                    if executor:
                        self._log(f"Redirected to {p.tag or p.device_ip}", "INFO")
                        break
        if executor is None:
            executor = self._ssh_executor
        if executor is None:
            self._log("No SSH executor — configure credentials in Attackers panel", "ERROR")
            return

        def _run():
            try:
                result = executor.execute(target_ip, cmd, timeout=120, use_sudo=use_sudo)
                if result.success:
                    self._log(f"Kali OK: {name} → {target_ip} ({result.duration:.1f}s)", "OK")
                    if result.output:
                        for line in result.output.splitlines()[:5]:
                            self._log(f"  {line}", "INFO")
                else:
                    self._log(f"Kali error: {name}: {result.error[:200]}", "ERROR")
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._log(f"SSH error: {e}", "ERROR")
        threading.Thread(target=_run, daemon=True).start()

    """
    Entrada: attack_def, target_ip (str), duration_s (int)
    Salida: None
    Descripción: Execute a plugin attack by dynamically importing and calling
                 its Python run() function in a background thread.
    """
    def _exec_plugin(self, attack_def, target_ip: str, duration_s: int) -> None:
        def _run():
            try:
                fallback = attack_def.local_fallback
                parts = fallback.split(":")
                mod_name = parts[0]
                func_name = parts[1] if len(parts) > 1 else "run"

                if mod_name.startswith("plugins.attacks."):
                    full_mod = mod_name
                elif mod_name.startswith("plugins."):
                    full_mod = mod_name
                else:
                    full_mod = f"plugins.attacks.{mod_name}"

                self._log(f"Plugin: {full_mod}.{func_name}()", "INFO")

                mod = importlib.import_module(full_mod)
                func = getattr(mod, func_name)

                result = func(
                    target_ip=target_ip,
                    port=80,
                    duration=duration_s or 30,
                )

                if isinstance(result, dict):
                    if result.get("success"):
                        self._log(f"Plugin OK: {attack_def.name} — {result.get('message', '')}", "OK")
                    else:
                        self._log(f"Plugin error: {result.get('message', 'unknown')}", "ERROR")
                else:
                    self._log(f"Plugin completed: {attack_def.name}", "OK")
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self._log(f"Plugin error: {attack_def.name}: {exc}", "ERROR")
        threading.Thread(target=_run, daemon=True).start()

    """
    Entrada: name (str), cmd (str), target_ip (str), duration_s (int), needs_root (bool)
    Salida: None
    Descripción: Run an attack command locally on this machine in a background
                 thread, using the LocalChannel.
    """
    def _exec_attack_local(self, name: str, cmd: str, target_ip: str,
                           duration_s: int, needs_root: bool = False) -> None:
        def _run():
            result = self._local.execute(
                target_ip=target_ip, command=cmd,
                timeout=duration_s + 30 if duration_s else 120,
                use_sudo=needs_root,
            )
            if result.success:
                self._log(f"Local OK: {name} → {target_ip}", "OK")
                if result.output:
                    for line in result.output.splitlines()[:5]:
                        self._log(f"  {line}", "INFO")
            else:
                self._log(f"Local error: {name}: {result.error[:200]}", "ERROR")
        threading.Thread(target=_run, daemon=True).start()

    """
    Entrada: msg (str), level (str)
    Salida: None
    Descripción: Forward a log message to the external logger callback if set.
    """
    def _log(self, msg: str, level: str = "INFO") -> None:
        if self._log_fn:
            self._log_fn(msg, level)
