from flask import request, abort
from lxml import etree

SCHEMA = etree.XMLSchema(etree.parse("schemas/shipment.xsd"))
PARSER = etree.XMLParser(schema=SCHEMA, resolve_entities=False)


def ingest():
    try:
        root = etree.fromstring(request.data, PARSER)
    except etree.XMLSyntaxError:
        abort(400)
    return root.findtext("id")
