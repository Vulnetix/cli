from flask import Flask, request
from defusedxml import ElementTree as ET

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_catalog():
    root = ET.fromstring(request.data)
    return str(len(root))
