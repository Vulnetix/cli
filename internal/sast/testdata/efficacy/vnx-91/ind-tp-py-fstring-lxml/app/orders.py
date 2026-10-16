from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/orders", methods=["POST"])
def create_order():
~>    doc = etree.fromstring(f"<order><id>{request.args['id']}</id><status>new</status></order>")
    return etree.tostring(doc)
