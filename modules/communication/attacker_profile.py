from __future__ import annotations
from dataclasses import dataclass


@dataclass
class AttackerProfile:
    device_ip: str = ""
    tag: str = ""
    mode: str = "local"
    ssh_user: str = "kali"
    ssh_port: int = 22
    ssh_key: str = ""
    ssh_password: str = ""   # runtime only

    def to_dict(self) -> dict:
        # NEVER include password
        return {
            "device_ip": self.device_ip, "tag": self.tag,
            "mode": self.mode, "ssh_user": self.ssh_user,
            "ssh_port": self.ssh_port, "ssh_key": self.ssh_key,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttackerProfile":
        return cls(
            device_ip=d.get("device_ip", ""), tag=d.get("tag", ""),
            mode=d.get("mode", "local"), ssh_user=d.get("ssh_user", "kali"),
            ssh_port=d.get("ssh_port", 22), ssh_key=d.get("ssh_key", ""),
        )

    @property
    def label(self) -> str:
        return self.tag or self.device_ip

    @property
    def is_local(self) -> bool:
        return self.mode == "local"

    @property
    def has_credentials(self) -> bool:
        return bool(self.ssh_password) or bool(self.ssh_key)
