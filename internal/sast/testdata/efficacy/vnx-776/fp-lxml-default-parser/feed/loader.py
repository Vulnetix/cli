from lxml import etree


def load(data):
    parser = etree.XMLParser(huge_tree=False, resolve_entities=False)
    return etree.fromstring(data, parser)


def load_default(request):
    return etree.fromstring(request.data)
