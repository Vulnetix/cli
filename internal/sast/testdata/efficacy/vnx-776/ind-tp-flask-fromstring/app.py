from flask import Flask, request, jsonify
import xml.etree.ElementTree as ET

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_catalog():
    payload = request.get_data()
    items = []
~>    root = ET.fromstring(payload)
    for node in root.findall("item"):
        items.append(node.get("sku"))
    return jsonify(items)
