import xml.etree.ElementTree as ET

from flask import request


def export():
    root = ET.Element("user")
    ET.SubElement(root, "name").text = request.args["name"]
    return ET.tostring(root)
