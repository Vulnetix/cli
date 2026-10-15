import xml.etree.ElementTree as ET
from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_orders():
~>    root = ET.fromstring(request.data)
    return {"orders": len(root.findall("order"))}


@app.route("/import2", methods=["POST"])
def import_orders_stream():
~>    tree = ET.parse(request.files["doc"].stream)
    return {"root": tree.getroot().tag}
