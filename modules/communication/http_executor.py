"""
HTTP Executor — sends HTTP requests to IoT devices
for benign actions (turn on, set brightness, etc).
"""
from __future__ import annotations
import time
import logging
import urllib.request
import urllib.error
from modules.communication.executor_base import BaseExecutor, ExecutionResult

logger = logging.getLogger(__name__)


class HTTPExecutor(BaseExecutor):
    """Send HTTP requests to IoT devices."""

    """
    Entrada: timeout (int)
    Salida: None
    Descripción: Initializes the HTTP executor with a request timeout.
    """
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    """
    Entrada: target_ip (str), command (str), port (int), method (str), endpoint (str), payload (str), headers (dict | None), **kwargs
    Salida: ExecutionResult
    Descripción: Sends an HTTP request to the target and returns the result.
    """
    def execute(self, target_ip: str, command: str, *,
                port: int = 80, method: str = "POST",
                endpoint: str = "/", payload: str = "",
                headers: dict | None = None, **kwargs) -> ExecutionResult:
        url = f"http://{target_ip}:{port}{endpoint}"
        logger.info("HTTP %s %s payload=%s", method, url, payload[:50])
        start = time.time()
        try:
            data = payload.encode("utf-8") if payload else None
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Content-Type", "application/json")
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                elapsed = time.time() - start
                logger.info("HTTP %d (%.1fs): %s", resp.status, elapsed, body[:100])
                return ExecutionResult(success=True, output=body, duration=elapsed)
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            return ExecutionResult(success=False, error=f"HTTP {e.code}: {e.reason}", duration=elapsed)
        except urllib.error.URLError as e:
            return ExecutionResult(success=False, error=f"URL error: {e.reason}")
        except (OSError, ValueError, TimeoutError) as exc:
            return ExecutionResult(success=False, error=str(exc))

    """
    Entrada: target_ip (str), port (int)
    Salida: bool
    Descripción: Tests HTTP connectivity to the target by issuing a GET request.
    """
    def test_connection(self, target_ip: str, port: int = 80) -> bool:
        result = self.execute(target_ip, "", port=port, method="GET", endpoint="/")
        return result.success

    """
    Entrada: device_ip (str), action, port (int)
    Salida: ExecutionResult
    Descripción: Execute a DeviceAction on a target device.
    """
    def send_action(self, device_ip: str, action, port: int = 80) -> ExecutionResult:
        return self.execute(
            target_ip=device_ip,
            command=action.name,
            port=port,
            method=action.method,
            endpoint=action.endpoint,
            payload=action.payload,
            headers=action.headers if action.headers else None,
        )
