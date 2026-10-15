from lxml import etree


def parse_manifest(data: bytes):
~>    parser = etree.XMLParser(
        remove_blank_text=True,
        attribute_defaults=True,
    )
    return etree.fromstring(data, parser)


def parse_strict(data: bytes):
~>    parser = etree.XMLParser(no_network=False,
                             dtd_validation=True)
    return etree.fromstring(data, parser)
