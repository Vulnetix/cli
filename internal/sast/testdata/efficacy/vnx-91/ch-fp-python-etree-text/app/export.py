import xml.etree.ElementTree as ET
from flask import Flask, request, Response

app = Flask(__name__)


@app.post("/export")
def export():
    root = ET.Element("order")
    qty = ET.SubElement(root, "qty")
    qty.text = request.form["qty"]
    # never: "<order><qty>" + request.form["qty"] + "</qty></order>"
    header = "<?xml version='1.0' encoding='utf-8'?>"
    return Response(header + ET.tostring(root, encoding="unicode"), mimetype="application/xml")
