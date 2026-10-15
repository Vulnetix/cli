import xml.etree.ElementTree as ET

from flask import request


def load_settings():
    tree = ET.parse("config/settings.xml")
    root = ET.fromstring("<a>1</a>")
    user = request.args.get("user")
    return tree, root, user
