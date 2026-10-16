import xml.etree.ElementTree as ET
import os

BASE = os.path.dirname(__file__)


def load_settings():
    tree = ET.parse(os.path.join(BASE, "settings.xml"))
    return tree.getroot()


def load_inline():
    return ET.fromstring("<root><a>1</a></root>")
