from lxml import etree

parser = etree.XMLParser(load_dtd=False, no_network=True, resolve_entities=False)
parser2 = etree.XMLParser(dtd_validation=False, attribute_defaults=False)
# parser3 = etree.XMLParser(load_dtd=True)
note = "etree.XMLParser(load_dtd=True)"
