from lxml import etree

PARSER = etree.XMLParser(huge_tree=False, resolve_entities=False)
# huge_tree=True is not allowed here; it disables libxml2 limits
SETTINGS = "<settings><mode>fast</mode></settings>"


def defaults():
    return etree.fromstring(SETTINGS, PARSER)
