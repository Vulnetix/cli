import xml.etree.ElementTree as ET
from flask import Flask, request

app = Flask(__name__)


@app.route("/inventory", methods=["POST"])
def inventory():
~>    for event, elem in ET.iterparse(request.files["sheet"].stream):
        if elem.tag == "row":
            elem.clear()
    return "ok"
