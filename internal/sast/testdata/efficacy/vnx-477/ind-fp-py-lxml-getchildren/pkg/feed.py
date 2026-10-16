from lxml import etree


def titles(xml_bytes):
    root = etree.fromstring(xml_bytes)
    return [c.text for c in root.getchildren() if c.tag == "title"]
