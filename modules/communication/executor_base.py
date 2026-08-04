"""Legacy shim — import from modules.comms.base instead."""
from modules.comms.base import BaseChannel as BaseExecutor, ChannelResult as ExecutionResult  # noqa: F401
