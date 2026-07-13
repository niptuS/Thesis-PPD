"""
Entrada: None
Salida: BUILTIN_PROFILES list
Descripción: Built-in benign profiles for common IoT device types.
             These define the actions the orchestrator can send to each device type.
"""
from modules.benign_profiles.profile_schema import BenignProfile, ActionDefinition, ActionParam


BUILTIN_PROFILES: list[BenignProfile] = [

    BenignProfile(
        device_type="bulb",
        display_name="💡 Smart Bulb",
        description="Philips Hue, LIFX, Tuya smart lights",
        actions=[
            ActionDefinition("turn_on", "Turn on light", "http", "PUT",
                             "/api/lights/{device_id}/state", '{"on": true}'),
            ActionDefinition("turn_of", "Turn off light", "http", "PUT",
                             "/api/lights/{device_id}/state", '{"on": false}'),
            ActionDefinition("set_brightness", "Set brightness", "http", "PUT",
                             "/api/lights/{device_id}/state", '{"bri": {level}}',
                             [ActionParam("level", "int", "254")]),
            ActionDefinition("set_color", "Set color", "http", "PUT",
                             "/api/lights/{device_id}/state",
                             '{"on": true, "hue": {hue}, "sat": {sat}}',
                             [ActionParam("hue", "int", "10000"), ActionParam("sat", "int", "254")]),
            ActionDefinition("blink", "Blink", "http", "PUT",
                             "/api/lights/{device_id}/state", '{"alert": "select"}'),
        ],
    ),

    BenignProfile(
        device_type="plug",
        display_name="🔌 Smart Plug",
        description="TP-Link Kasa, Meross, Sonoff plugs",
        actions=[
            ActionDefinition("turn_on", "Turn on plug", "http", "POST",
                             "/api/relay/0", '{"state": "on"}'),
            ActionDefinition("turn_of", "Turn off plug", "http", "POST",
                             "/api/relay/0", '{"state": "off"}'),
            ActionDefinition("toggle", "Toggle state", "http", "POST",
                             "/api/relay/0/toggle", ""),
            ActionDefinition("get_power", "Read power", "http", "GET",
                             "/api/meter/0", ""),
        ],
    ),

    BenignProfile(
        device_type="camera",
        display_name="📷 IP Camera",
        description="Hikvision, Dahua, Reolink cameras",
        actions=[
            ActionDefinition("start_stream", "Start RTSP stream", "http", "GET",
                             "/ISAPI/Streaming/channels/101", ""),
            ActionDefinition("stop_stream", "Stop stream", "http", "PUT",
                             "/ISAPI/Streaming/channels/101/stop", ""),
            ActionDefinition("snapshot", "Take snapshot", "http", "GET",
                             "/ISAPI/Streaming/channels/101/picture", ""),
            ActionDefinition("ptz_move", "Move PTZ camera", "http", "PUT",
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
            ActionDefinition("play_audio", "Play audio", "http", "POST",
                             "/api/play", '{"url": "{url}"}',
                             [ActionParam("url", "str", "http://example.com/audio.mp3")]),
            ActionDefinition("set_volume", "Set volume", "http", "POST",
                             "/api/volume", '{"level": {level}}',
                             [ActionParam("level", "int", "50")]),
            ActionDefinition("stop", "Stop playback", "http", "POST",
                             "/api/stop", ""),
        ],
    ),

    BenignProfile(
        device_type="sensor",
        display_name="📡 IoT Sensor",
        description="Temperature, humidity, motion (MQTT)",
        actions=[
            ActionDefinition("read_value", "Read sensor", "mqtt", "SUB",
                             "sensors/{device_id}/data", ""),
            ActionDefinition("request_report", "Request report", "mqtt", "PUB",
                             "sensors/{device_id}/cmd", '{"action": "report"}'),
            ActionDefinition("set_interval", "Set interval", "mqtt", "PUB",
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
            ActionDefinition("get_status", "Get hub status", "http", "GET",
                             "/api/status", ""),
            ActionDefinition("list_devices", "List devices", "http", "GET",
                             "/api/devices", ""),
            ActionDefinition("send_command", "Send command", "ssh", "EXEC",
                             "", "{command}",
                             [ActionParam("command", "str", "echo ok", True)]),
        ],
    ),
]


def get_profile_for_type(device_type: str) -> BenignProfile | None:
    """
    Entrada: device_type (str)
    Salida: BenignProfile | None
    Descripción: Returns the built-in profile matching the given device type.
    """
    return next((p for p in BUILTIN_PROFILES if p.device_type == device_type), None)


def get_all_device_types() -> list[str]:
    """
    Entrada: None
    Salida: list[str]
    Descripción: Returns all device type keys defined in BUILTIN_PROFILES.
    """
    return [p.device_type for p in BUILTIN_PROFILES]
