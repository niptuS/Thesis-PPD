"""
Built-in benign profiles for common IoT device types.
These define the actions the orchestrator can send to each device type.
"""
from modules.benign_profiles.profile_schema import BenignProfile, ActionDefinition, ActionParam


BUILTIN_PROFILES: list[BenignProfile] = [

    BenignProfile(
        device_type="bulb",
        display_name="💡 Smart Bulb",
        description="Philips Hue, LIFX, Tuya smart lights",
        actions=[
            ActionDefinition("turn_on", "Encender luz", "http", "PUT",
                             "/api/lights/{device_id}/state", '{"on": true}'),
            ActionDefinition("turn_of", "Apagar luz", "http", "PUT",
                             "/api/lights/{device_id}/state", '{"on": false}'),
            ActionDefinition("set_brightness", "Cambiar brillo", "http", "PUT",
                             "/api/lights/{device_id}/state", '{"bri": {level}}',
                             [ActionParam("level", "int", "254")]),
            ActionDefinition("set_color", "Cambiar color", "http", "PUT",
                             "/api/lights/{device_id}/state",
                             '{"on": true, "hue": {hue}, "sat": {sat}}',
                             [ActionParam("hue", "int", "10000"), ActionParam("sat", "int", "254")]),
            ActionDefinition("blink", "Parpadear", "http", "PUT",
                             "/api/lights/{device_id}/state", '{"alert": "select"}'),
        ],
    ),

    BenignProfile(
        device_type="plug",
        display_name="🔌 Smart Plug",
        description="TP-Link Kasa, Meross, Sonoff plugs",
        actions=[
            ActionDefinition("turn_on", "Encender enchufe", "http", "POST",
                             "/api/relay/0", '{"state": "on"}'),
            ActionDefinition("turn_of", "Apagar enchufe", "http", "POST",
                             "/api/relay/0", '{"state": "off"}'),
            ActionDefinition("toggle", "Alternar estado", "http", "POST",
                             "/api/relay/0/toggle", ""),
            ActionDefinition("get_power", "Leer consumo", "http", "GET",
                             "/api/meter/0", ""),
        ],
    ),

    BenignProfile(
        device_type="camera",
        display_name="📷 IP Camera",
        description="Hikvision, Dahua, Reolink cameras",
        actions=[
            ActionDefinition("start_stream", "Iniciar stream RTSP", "http", "GET",
                             "/ISAPI/Streaming/channels/101", ""),
            ActionDefinition("stop_stream", "Detener stream", "http", "PUT",
                             "/ISAPI/Streaming/channels/101/stop", ""),
            ActionDefinition("snapshot", "Capturar imagen", "http", "GET",
                             "/ISAPI/Streaming/channels/101/picture", ""),
            ActionDefinition("ptz_move", "Mover cámara PTZ", "http", "PUT",
                             "/ISAPI/PTZCtrl/channels/1/continuous",
                             '<PTZData><pan>{pan}</pan><tilt>{tilt}</tilt></PTZData>',
                             [ActionParam("pan", "int", "50"), ActionParam("tilt", "int", "0")]),
        ],
    ),

    BenignProfile(
        device_type="speaker",
        display_name="🔊 Smart Speaker",
        description="Echo, Google Home, Sonos",
        actions=[
            ActionDefinition("play_audio", "Reproducir audio", "http", "POST",
                             "/api/play", '{"url": "{url}"}',
                             [ActionParam("url", "str", "http://example.com/audio.mp3")]),
            ActionDefinition("set_volume", "Cambiar volumen", "http", "POST",
                             "/api/volume", '{"level": {level}}',
                             [ActionParam("level", "int", "50")]),
            ActionDefinition("stop", "Detener reproducción", "http", "POST",
                             "/api/stop", ""),
        ],
    ),

    BenignProfile(
        device_type="sensor",
        display_name="📡 IoT Sensor",
        description="Temperatura, humedad, movimiento (MQTT)",
        actions=[
            ActionDefinition("read_value", "Leer sensor", "mqtt", "SUB",
                             "sensors/{device_id}/data", ""),
            ActionDefinition("request_report", "Solicitar reporte", "mqtt", "PUB",
                             "sensors/{device_id}/cmd", '{"action": "report"}'),
            ActionDefinition("set_interval", "Cambiar intervalo", "mqtt", "PUB",
                             "sensors/{device_id}/config",
                             '{"interval_s": {seconds}}',
                             [ActionParam("seconds", "int", "60")]),
        ],
    ),

    BenignProfile(
        device_type="hub",
        display_name="🏠 Smart Hub",
        description="Raspberry Pi, SmartThings hub",
        actions=[
            ActionDefinition("get_status", "Estado del hub", "http", "GET",
                             "/api/status", ""),
            ActionDefinition("list_devices", "Listar dispositivos", "http", "GET",
                             "/api/devices", ""),
            ActionDefinition("send_command", "Enviar comando", "ssh", "EXEC",
                             "", "{command}",
                             [ActionParam("command", "str", "echo ok", True)]),
        ],
    ),
]


def get_profile_for_type(device_type: str) -> BenignProfile | None:
    return next((p for p in BUILTIN_PROFILES if p.device_type == device_type), None)


def get_all_device_types() -> list[str]:
    return [p.device_type for p in BUILTIN_PROFILES]
