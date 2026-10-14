import xmltodict
from lxml import etree

~>parser = etree.XMLParser(resolve_entities=True, no_network=False)
lenient = etree.XMLParser(
    load_dtd=True,
~>    no_network=False,
)


def parse(data):
    return etree.fromstring(data, parser)


def to_dict(data):
~>    return xmltodict.parse(data, disable_entities=False)
