import lxml.etree as ET


def lookup(root, title):
~>    nodes = root.xpath("//item[title='" + title + "']")
    return [n.get("id") for n in nodes]
