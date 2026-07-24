"""
MQTT Client — publishes/subscribes to IoT sensor topics.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MQTTResult:
    success: bool
    message: str = ""
    error: str = ""


class MQTTClient:
    """MQTT publish/subscribe for IoT sensors."""

    """
    Entrada: broker (str), port (int), username (str), password (str)
    Salida: None
    Descripción: Initializes the MQTT client with broker connection parameters.
    """
    def __init__(self, broker: str = "localhost", port: int = 1883,
                 username: str = "", password: str = "") -> None:
        self.broker = broker
        self.port = port
        self.username = username
        self.password = password
        self._client = None

    """
    Entrada: None
    Salida: bool
    Descripción: Connects to the MQTT broker and starts the network loop.
    """
    def connect(self) -> bool:
        try:
            import paho.mqtt.client as mqtt
            self._client = mqtt.Client()
            if self.username:
                self._client.username_pw_set(self.username, self.password)
            self._client.connect(self.broker, self.port, keepalive=60)
            self._client.loop_start()
            logger.info("MQTT connected to %s:%d", self.broker, self.port)
            return True
        except ImportError:
            logger.error("paho-mqtt not installed: pip install paho-mqtt")
            return False
        except Exception as exc:
            logger.error("MQTT connection failed: %s", exc)
            return False

    """
    Entrada: topic (str), payload (str)
    Salida: MQTTResult
    Descripción: Publishes a payload to the given MQTT topic.
    """
    def publish(self, topic: str, payload: str = "") -> MQTTResult:
        if self._client is None:
            return MQTTResult(success=False, error="not connected")
        try:
            result = self._client.publish(topic, payload)
            result.wait_for_publish(timeout=5)
            logger.info("MQTT PUB %s → %s", topic, payload[:50])
            return MQTTResult(success=True, message=f"published to {topic}")
        except Exception as exc:
            return MQTTResult(success=False, error=str(exc))

    """
    Entrada: None
    Salida: None
    Descripción: Stops the network loop and disconnects from the broker.
    """
    def close(self) -> None:
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
            self._client = None
