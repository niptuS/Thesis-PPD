"""
MQTT Executor — publishes commands to IoT devices via MQTT broker.
"""
from __future__ import annotations
import time
import logging
from modules.communication.executor_base import BaseExecutor, ExecutionResult

logger = logging.getLogger(__name__)


class MQTTExecutor(BaseExecutor):
    """Publish MQTT messages to IoT devices."""

    def __init__(self, broker_host: str = "localhost", broker_port: int = 1883):
        self.broker_host = broker_host
        self.broker_port = broker_port

    def execute(self, target_ip: str, command: str, topic: str = "",
                payload: str = "", **kwargs) -> ExecutionResult:
        logger.info("MQTT PUB → %s topic=%s payload=%s", self.broker_host, topic, payload[:50])
        start = time.time()
        try:
            import paho.mqtt.publish as publish
            publish.single(
                topic=topic or command,
                payload=payload,
                hostname=self.broker_host,
                port=self.broker_port,
            )
            elapsed = time.time() - start
            logger.info("MQTT OK (%.1fs)", elapsed)
            return ExecutionResult(success=True, output="published", duration=elapsed)
        except ImportError:
            return ExecutionResult(success=False, error="paho-mqtt required: pip install paho-mqtt")
        except (OSError, IOError, ConnectionError, TimeoutError) as e:
            return ExecutionResult(success=False, error=str(e))

    def test_connection(self, target_ip: str = "") -> bool:
        try:
            import paho.mqtt.client as mqtt
            client = mqtt.Client()
            client.connect(self.broker_host, self.broker_port, keepalive=5)
            client.disconnect()
            return True
        except (OSError, ConnectionError, TimeoutError, ValueError):
            return False

    def send_action(self, action, payload: str = "") -> ExecutionResult:
        return self.execute(
            target_ip="",
            command=action.name,
            topic=action.endpoint,
            payload=payload or action.payload,
        )
