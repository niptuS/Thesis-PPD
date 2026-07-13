"""Base class for attack modules — maps to real Kali Linux tools."""
from __future__ import annotations
import shutil
from dataclasses import dataclass


@dataclass
class AttackResult:
    success: bool
    output: str = ""
    error: str = ""
    packets: int = 0
    duration: float = 0.0


@dataclass
class AttackDef:
    """Definition of an attack: metadata + Kali command template."""
    name: str
    description: str
    mitre_ref: str
    tool: str
    category: str
    command: str
    requires_root: bool = True
    recommended_dur_s: int = 30
    continuous:     bool = False
    kill_chain:    str  = ""
    subcategory:   str  = ""
    local_fallback: str = ""

    """
    Entrada: target_ip (str), duration (int), intensity (str), port (int), gateway (str), **kwargs
    Salida: str
    Descripción: Build the actual command string from the template.
    """
    def build_command(self, target_ip: str, *, duration: int = 30,
                      intensity: str = "medium", port: int = 80,
                      gateway: str = "", **kwargs) -> str:
        return self.command.format(
            target=target_ip,
            port=port,
            duration=duration,
            intensity=intensity,
            gateway=gateway,
            **kwargs,
        )




_TOOL_VARIANTS: dict[str, list[str]] = {
    "coap-client": ["coap-client", "coap-client-openssl", "coap-client-gnutls"],
}


"""
Entrada: tool (str), ssh_executor
Salida: bool
Descripción: Check if a tool is available on the remote SSH host.
"""
def check_tool_ssh(tool: str, ssh_executor) -> bool:
    variants = _TOOL_VARIANTS.get(tool, [tool])
    for name in variants:
        try:
            result = ssh_executor.execute("", f"which {name} 2>/dev/null", timeout=10)
            if result.success and result.output and "not found" not in result.output:
                return True
        except (OSError, RuntimeError, TimeoutError):
            continue
    return False


"""
Entrada: tool (str)
Salida: bool
Descripción: Check if a tool is available locally.
"""
def check_tool_local(tool: str) -> bool:
    variants = _TOOL_VARIANTS.get(tool, [tool])
    for name in variants:
        if shutil.which(name):
            return True
    return False
