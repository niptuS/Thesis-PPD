"""
Entrada: None
Salida: HTTPChannel class
Descripción: HTTP channel — sends HTTP/HTTPS requests to IoT devices for
             benign actions (turn on, set brightness, etc). Merges the
             previous HTTPExecutor and HTTPClient into a single channel.
"""
from __future__ import annotations
import time
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass
from modules.comms.base import BaseChannel, ChannelResult

logger = logging.getLogger(__name__)


@dataclass
class HTTPResult:
    """
    Entrada: success (bool), status_code (int), body (str), error (str)
    Salida: HTTPResult instance
    Descripción: Rich HTTP-specific result with status code and body, kept for
                 callers that need the HTTP status code (e.g. endpoint scanner).
    """
    success: bool
    status_code: int = 0
    body: str = ""
    error: str = ""


class HTTPChannel(BaseChannel):
    """
    Entrada: timeout (int)
    Salida: None
    Descripción: Initializes the HTTP channel with a request timeout.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    """
    Entrada: target_ip, command, port, method, endpoint,
             payload, headers, **kwargs
    Salida: ChannelResult
    Descripción: Sends an HTTP request to the target and returns
                 a ChannelResult.
    """
    def execute(self, target_ip: str, command: str, *,
                port: int = 80, method: str = "POST",
                endpoint: str = "/", payload: str = "",
                headers: dict | None = None, **kwargs) -> ChannelResult:
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
                return ChannelResult(success=True, output=body, duration=elapsed)
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            return ChannelResult(
                success=False, error=f"HTTP {e.code}: {e.reason}", duration=elapsed,
            )
        except urllib.error.URLError as e:
            return ChannelResult(success=False, error=f"URL error: {e.reason}")
        except (OSError, ValueError, TimeoutError) as exc:
            return ChannelResult(success=False, error=str(exc))

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
    Salida: ChannelResult
    Descripción: Convenience method: execute a DeviceAction on a target device.
    """
    def send_action(self, device_ip: str, action, port: int = 80) -> ChannelResult:
        return self.execute(
            target_ip=device_ip,
            command=action.name,
            port=port,
            method=action.method,
            endpoint=action.endpoint,
            payload=action.payload,
            headers=action.headers if action.headers else None,
        )

    # ── HTTPResult-returning variant (used by endpoint scanner) ─────────────

    """
    Entrada: method (str), url (str), payload (str), headers (dict | None), auth_user (str), auth_pass (str)
    Salida: HTTPResult
    Descripción: Low-level request method returning a rich HTTPResult with the
                 HTTP status code. Used by the endpoint scanner which needs
                 the status code to distinguish 200/401/403/404.
    """
    def request(self, method: str, url: str, payload: str = "",
                headers: dict | None = None,
                auth_user: str = "", auth_pass: str = "") -> HTTPResult:
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        if auth_user:
            import base64
            cred = base64.b64encode(
                f"{auth_user}:{auth_pass}".encode()
            ).decode()
            hdrs["Authorization"] = f"Basic {cred}"

        data = payload.encode() if payload else None
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode(errors="replace")
                logger.info("HTTP %s %s → %d", method, url, resp.status)
                return HTTPResult(success=True, status_code=resp.status, body=body)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace") if exc.fp else ""
            return HTTPResult(
                success=False, status_code=exc.code, body=body, error=str(exc),
            )
        except Exception as exc:
            return HTTPResult(success=False, error=str(exc))
