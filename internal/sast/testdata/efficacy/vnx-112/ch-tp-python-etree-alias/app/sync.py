import xml.etree.ElementTree as ET

from defusedxml import ElementTree as DET
from flask import Flask, request

app = Flask(__name__)


@app.post("/sync")
def sync():
~>    root = ET.fromstring(request.data)
    items = [n.text for n in root.iter("item")]
    return {"count": len(items)}


@app.post("/upload")
def upload():
    raw = request.files["doc"].read()
~>    tree = DET.fromstring(raw)
    return {"tag": tree.tag}
