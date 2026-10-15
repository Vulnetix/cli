from lxml import etree


def build_parser():
    return etree.XMLParser(
        resolve_entities=False,
~>        huge_tree=True,
        remove_blank_text=True,
    )
