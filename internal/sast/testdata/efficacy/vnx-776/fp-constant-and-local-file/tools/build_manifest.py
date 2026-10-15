import xml.etree.ElementTree as ET
from xml.dom import minidom


def manifest(path):
    tree = ET.parse("config/manifest.xml")
    other = ET.parse(path)
    template = ET.fromstring("<root><item/></root>")
    pretty = minidom.parseString(ET.tostring(template)).toprettyxml()
    elem = ET.Element("entry")
    return tree, other, pretty, elem
