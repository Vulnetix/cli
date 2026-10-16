import xml.etree.ElementTree as ET

import requests
from flask import request


def reserve():
    qty = request.form.get("qty")
    sku = request.form.get("sku")
~>    line = "<qty>%s</qty>" % qty
~>    item = "<item><sku>{}</sku>".format(sku) + line + "</item>"
    root = ET.fromstring("<reserve>" + item + "</reserve>")
    requests.post("https://wms.internal/reserve", data=ET.tostring(root), headers={"Content-Type": "application/xml"})
    return "ok"
