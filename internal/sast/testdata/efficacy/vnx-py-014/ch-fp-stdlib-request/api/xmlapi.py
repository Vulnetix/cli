import xml.etree.ElementTree as ET
from xml.dom import minidom

from flask import Flask, request

app = Flask(__name__)


@app.post("/order")
def order():
    root = ET.fromstring(request.data)
    pretty = minidom.parseString(request.data).toprettyxml()
    return {"id": root.get("id"), "pretty": pretty}
