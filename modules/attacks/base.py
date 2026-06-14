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
    tool: str           # Kali tool: hping3, nmap, hydra, etc.
    category: str           # dos, recon, mitm, brute_force, etc.
    command: str      # command template with {target}, {port}, {duration}, {intensity}, {gateway}
    requires_root: bool = True
    recommended_dur_s: int = 30   # recommended duration in seconds
    # local Python fallback (when no Kali available)
    local_fallback: str = ""    # Python module function path, empty = no local fallback

    def build_command(self, target_ip: str, *, duration: int = 30,
                      intensity: str = "medium", port: int = 80,
                      gateway: str = "", **kwargs) -> str:
        """Build the actual command string from the template."""
        return self.command.format(
            target=target_ip,
            port=port,
            duration=duration,
            intensity=intensity,
            gateway=gateway,
            **kwargs,
        )


# ── Tool verification ───────────────────────────────────────────


# Some tools have variant binary names (e.g. coap-client-openssl)
_TOOL_VARIANTS: dict[str, list[str]] = {
    "coap-client": ["coap-client", "coap-client-openssl", "coap-client-gnutls"],
}


def check_tool_ssh(tool: str, ssh_executor) -> bool:
    """Check if a tool is available on the remote SSH host."""
    variants = _TOOL_VARIANTS.get(tool, [tool])
    for name in variants:
        try:
            result = ssh_executor.execute("", f"which {name} 2>/dev/null", timeout=10)
            if result.success and result.output and "not found" not in result.output:
                return True
        except (OSError, RuntimeError, TimeoutError):
            continue
    return False


def check_tool_local(tool: str) -> bool:
    """Check if a tool is available locally."""
    variants = _TOOL_VARIANTS.get(tool, [tool])
    for name in variants:
        if shutil.which(name):
            return True
    return False
