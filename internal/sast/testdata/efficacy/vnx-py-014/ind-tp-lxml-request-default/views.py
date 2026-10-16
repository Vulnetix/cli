from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_xml():
~>    root = etree.fromstring(request.data)
    return root.tag
