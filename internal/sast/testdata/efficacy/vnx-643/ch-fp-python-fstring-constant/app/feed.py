import xml.etree.ElementTree as ET

NS = "{http://www.w3.org/2005/Atom}"


def entries(root):
    log.info(f"parsing feed with {len(root)} children")
    return root.findall(f"{NS}entry")


def message(name):
    return "root.xpath(\"//user[@name='\" + name + \"']\") is unsafe"
