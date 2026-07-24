"""
Entrada: None
Salida: MQTTChannel class
Descripción: MQTT channel — publishes commands to IoT devices via an MQTT
             broker. Merges the previous MQTTExecutor and MQTTClient.
"""
from __future__ import annotations
import time
import logging
from dataclasses import dataclass
from modules.comms.base import BaseChannel, ChannelResult

logger = logging.getLogger(__name__)


@dataclass
class MQTTResult:
    """
    Entrada: success (bool), message (str), error (str)
    Salida: MQTTResult instance
    Descripción: Rich MQTT-specific result with a human-readable message.
    """
    success: bool
    message: str = ""
    error: str = ""


class MQTTChannel(BaseChannel):
    """
    Entrada: broker_host (str), broker_port (int)
    Salida: None
    Descripción: Initializes the MQTT channel with broker connection parameters.
    """

    def __init__(self, broker_host: str = "localhost", broker_port: int = 1883):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self._client = None

    """
    Entrada: target_ip (str), command (str), topic (str), payload (str), **kwargs
    Salida: ChannelResult
    Descripción: Publishes an MQTT message to the broker and returns the result.
    """
    def execute(self, target_ip: str, command: str, topic: str = "",
                payload: str = "", **kwargs) -> ChannelResult:
        logger.info("MQTT PUB → %s topic=%s payload=%s",
                    self.broker_host, topic, payload[:50])
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
            return ChannelResult(success=True, output="published", duration=elapsed)
        except ImportError:
            return ChannelResult(
                success=False, error="paho-mqtt required: pip install paho-mqtt",
            )
        except (OSError, IOError, ConnectionError, TimeoutError) as e:
            return ChannelResult(success=False, error=str(e))

    """
    Entrada: target_ip (str)
    Salida: bool
    Descripción: Tests MQTT broker connectivity by opening and closing a
                 client connection.
    """
    def test_connection(self, target_ip: str = "") -> bool:
        try:
            import paho.mqtt.client as mqtt
            client = mqtt.Client()
            client.connect(self.broker_host, self.broker_port, keepalive=5)
            client.disconnect()
            return True
        except (OSError, ConnectionError, TimeoutError, ValueError):
            return False

    """
    Entrada: action, payload (str)
    Salida: ChannelResult
    Descripción: Convenience method: publish a DeviceAction via MQTT to its
                 endpoint topic.
    """
    def send_action(self, action, payload: str = "") -> ChannelResult:
        return self.execute(
            target_ip="",
            command=action.name,
            topic=action.endpoint,
            payload=payload or action.payload,
        )

    # ── MQTTResult-returning variant (used by some callers) ────────────────

    """
    Entrada: topic (str), payload (str)
    Salida: MQTTResult
    Descripción: Publishes a payload to the given MQTT topic, returning a
                 rich MQTTResult. Keeps a persistent client connection.
    """
    def publish(self, topic: str, payload: str = "") -> MQTTResult:
        if self._client is None:
            connected = self._connect_persistent()
            if not connected:
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
    Salida: bool
    Descripción: Connects to the broker and starts the network loop. Used by
                 the persistent publish() variant.
    """
    def _connect_persistent(self) -> bool:
        try:
            import paho.mqtt.client as mqtt
            self._client = mqtt.Client()
            self._client.connect(self.broker_host, self.broker_port, keepalive=60)
            self._client.loop_start()
            logger.info("MQTT connected to %s:%d", self.broker_host, self.broker_port)
            return True
        except ImportError:
            logger.error("paho-mqtt not installed: pip install paho-mqtt")
            return False
        except Exception as exc:
            logger.error("MQTT connection failed: %s", exc)
            return False

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
