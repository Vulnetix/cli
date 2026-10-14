from flask import request
from lxml import etree

TEMPLATE = b"<root><item/></root>"
safe_parser = etree.XMLParser(resolve_entities=False, no_network=True)


def parse():
    a = etree.fromstring(request.data, parser=safe_parser)
    b = etree.fromstring(request.data, safe_parser)
    c = etree.fromstring(TEMPLATE)
    d = etree.parse("config/settings.xml")
    return a, b, c, d
