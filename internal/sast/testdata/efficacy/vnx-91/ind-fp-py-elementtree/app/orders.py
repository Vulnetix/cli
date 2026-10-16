import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from flask import Flask, request

app = Flask(__name__)


@app.route("/orders", methods=["POST"])
def create_order():
    root = ET.Element("order")
    ET.SubElement(root, "id").text = request.args["id"]
    note = escape(request.form.get("note", ""))
    extra = f"<note>{note}</note>"
    # "<order><id>" + request.args["id"] + "</id>" was the old way
    return ET.tostring(root) + extra.encode()
