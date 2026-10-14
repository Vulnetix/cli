import io

from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_xml():
~>    root = etree.fromstring(request.data)
    return root.tag


@app.route("/import2", methods=["POST"])
def import_file():
    body = request.files["doc"].read()
~>    tree = etree.parse(io.BytesIO(body))
    return tree.getroot().tag
