from flask import Flask, request
from lxml import etree

app = Flask(__name__)
SCHEMA = etree.XMLSchema(etree.parse("schemas/feed.xsd"))
PARSER = etree.XMLParser(schema=SCHEMA, resolve_entities=False)


@app.route("/import", methods=["POST"])
def import_feed():
    root = etree.fromstring(request.data, PARSER)
    return str(len(root))
