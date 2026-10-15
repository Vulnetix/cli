from flask import Flask, request
from lxml import etree
import xml.etree.ElementTree as ET

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_feed():
    parser = etree.XMLParser(resolve_entities=False)
~>    root = etree.fromstring(request.data, parser)
    payload = request.get_data()
~>    other = ET.fromstring(payload)
    return str(len(root) + len(other))
