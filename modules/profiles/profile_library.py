"""Built-in benign action templates for IoT device types."""
from modules.profiles.profile_schema import BenignProfile

DEVICE_TYPES = [
    "camera", "bulb", "plug", "sensor", "speaker",
    "thermostat", "lock", "doorbell", "vacuum",
    "tv", "hub", "irrigation", "garage", "alarm",
    "blind", "appliance",
]


def create_template_profile(device_type, device_ip="", device_tag=""):
    return BenignProfile(
        device_type=device_type, device_ip=device_ip,
        device_tag=device_tag, actions=[],
    )
