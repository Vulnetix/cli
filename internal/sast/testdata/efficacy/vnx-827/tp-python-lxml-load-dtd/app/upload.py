from lxml import etree


def parse_upload(data):
~>    parser = etree.XMLParser(load_dtd=True)
    return etree.fromstring(data, parser)


def parse_validated(data):
~>    parser = etree.XMLParser(remove_blank_text=True, dtd_validation=True)
    return etree.fromstring(data, parser)


def parse_multiline(data):
~>    parser = etree.XMLParser(
        load_dtd = True,
        no_network=False,
    )
    return etree.fromstring(data, parser)
