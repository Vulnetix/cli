import defusedxml.ElementTree as DET
import xml.etree.ElementTree as ET
from lxml import etree


def parse(body, request_body):
    a = DET.fromstring(body)
    b = ET.fromstring(body)
    c = etree.fromstring(request_body, etree.XMLParser(resolve_entities=False))
    d = etree.parse("config/static.xml")
    return a, b, c, d
