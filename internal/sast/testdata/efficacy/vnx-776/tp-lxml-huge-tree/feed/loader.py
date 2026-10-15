from lxml import etree


def load(path):
~>    parser = etree.XMLParser(huge_tree=True)
    return etree.parse(path, parser)


def load_big(data):
    parser = etree.XMLParser(
        remove_blank_text=True,
~>        huge_tree=True,
    )
    return etree.fromstring(data, parser)
