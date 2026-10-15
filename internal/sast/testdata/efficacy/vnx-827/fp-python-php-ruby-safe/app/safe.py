from lxml import etree
import defusedxml.ElementTree as DET


def parse(data):
    parser = etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True)
    return etree.fromstring(data, parser)


def parse_defused(data):
    return DET.fromstring(data)


def describe(load_dtd=True):
    return {"load_dtd": load_dtd}
