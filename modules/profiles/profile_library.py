"""Built-in benign action templates for IoT device types."""
from modules.profiles.profile_schema import BenignProfile

DEVICE_TYPES = [
    "camera", "bulb", "plug", "sensor", "speaker",
    "thermostat", "lock", "doorbell", "vacuum",
    "tv", "hub", "irrigation", "garage", "alarm",
    "blind", "appliance",
]


"""
Entrada: device_type, device_ip (str), device_tag (str)
Salida: BenignProfile
Descripción: Creates an empty template benign profile for the given device type.
"""
def create_template_profile(device_type, device_ip="", device_tag=""):
    return BenignProfile(
        device_type=device_type, device_ip=device_ip,
        device_tag=device_tag, actions=[],
    )
