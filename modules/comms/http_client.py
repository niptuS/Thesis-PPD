"""
HTTP Client — sends commands to IoT devices via HTTP/HTTPS.
"""
from __future__ import annotations
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class HTTPResult:
    success: bool
    status_code: int = 0
    body: str = ""
    error: str = ""


class HTTPClient:
    """Sends HTTP requests to IoT devices."""

    def __init__(self, base_url: str = "", auth_user: str = "",
                 auth_pass: str = "", timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.timeout = timeout

    def request(self, method: str, endpoint: str, payload: str = "",
                headers: dict | None = None) -> HTTPResult:
        url = f"{self.base_url}{endpoint}"
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)

        # basic auth
        if self.auth_user:
            import base64
            cred = base64.b64encode(f"{self.auth_user}:{self.auth_pass}".encode()).decode()
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
            return HTTPResult(success=False, status_code=exc.code, body=body, error=str(exc))
        except Exception as exc:
            return HTTPResult(success=False, error=str(exc))

    def get(self, endpoint: str) -> HTTPResult:
        return self.request("GET", endpoint)

    def post(self, endpoint: str, payload: str = "") -> HTTPResult:
        return self.request("POST", endpoint, payload)

    def put(self, endpoint: str, payload: str = "") -> HTTPResult:
        return self.request("PUT", endpoint, payload)
