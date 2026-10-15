import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).parent


def load():
    tree = ET.parse(HERE / "defaults.xml")
    return tree.getroot()
