from lxml import etree


def parse_catalog(path):
    parser = etree.XMLParser(
        remove_blank_text=True,
~>        resolve_entities=True,
    )
    return etree.parse(path, parser)


def parse_remote(path):
~>    parser = etree.XMLParser(load_dtd=True, no_network=False)
    return etree.parse(path, parser)
