from lxml import etree

SAFE = etree.XMLParser(resolve_entities=False, no_network=True)


def read(request):
    return etree.fromstring(request.data, SAFE)
