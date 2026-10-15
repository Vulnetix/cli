import xml.etree.ElementTree as ET

root = ET.parse("catalog.xml").getroot()


def by_author(author):
~>    return root.findall(".//book[@author='" + author + "']")


def first_title(isbn):
~>    node = root.find(f".//book[@isbn='{isbn}']/title")
    return node.text if node is not None else None
