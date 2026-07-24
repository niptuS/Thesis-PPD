"""Legacy shim — import from modules.comms.ssh_channel instead."""
from modules.comms.ssh_channel import SSHChannel as SSHExecutor  # noqa: F401
