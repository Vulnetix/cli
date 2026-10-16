from lxml import etree


def doc(data):
~>    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    return etree.fromstring(data, parser)
