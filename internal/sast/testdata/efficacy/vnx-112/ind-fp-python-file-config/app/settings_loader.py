import xml.etree.ElementTree as ET
from pathlib import Path

from defusedxml import minidom

CONFIG = Path(__file__).parent / "config" / "settings.xml"
DEFAULTS = "<settings><timeout>30</timeout></settings>"


def load_settings():
    tree = ET.parse("config/settings.xml")
    defaults = ET.fromstring(DEFAULTS)
    feeds = minidom.parseString(CONFIG.read_text())
    return tree.getroot(), defaults, feeds
