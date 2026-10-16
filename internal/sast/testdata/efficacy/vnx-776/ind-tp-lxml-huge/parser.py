from lxml import etree


def build_parser():
    # allow very large documents from partners
~>    return etree.XMLParser(huge_tree=True, remove_comments=True)
