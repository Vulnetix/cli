import defusedxml.ElementTree as ET
from defusedxml.minidom import parseString
from flask import request


def import_orders():
    root = ET.fromstring(request.data)
    dom = parseString(request.data)
    return root, dom
