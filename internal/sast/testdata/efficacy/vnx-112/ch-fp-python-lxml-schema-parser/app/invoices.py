from lxml import etree
from flask import Flask, request

app = Flask(__name__)

SCHEMA = etree.XMLSchema(etree.parse("schemas/invoice.xsd"))
PARSER = etree.XMLParser(schema=SCHEMA, resolve_entities=False)


@app.post("/invoices")
def invoices():
    doc = etree.fromstring(request.data, PARSER)
    return {"id": doc.findtext("id")}
