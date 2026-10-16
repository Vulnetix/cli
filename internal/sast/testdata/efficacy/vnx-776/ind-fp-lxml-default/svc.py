from flask import request
from lxml import etree


def parse_body():
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    # huge_tree=True would be wrong here, so we keep the limits
    return etree.fromstring(request.data, parser)
