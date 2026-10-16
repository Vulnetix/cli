from lxml import etree


def load(path):
~>    parser = etree.XMLParser(load_dtd=True, resolve_entities=False)
    return etree.parse(path, parser)


def load_validating(path):
~>    parser = etree.XMLParser(
        remove_comments=True,
        dtd_validation=True,
    )
    return etree.parse(path, parser)
