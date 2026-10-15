import xml.etree.ElementTree as ET

# Never do ET.fromstring(request.data) on untrusted input: use defusedxml.
HELP = "ET.fromstring(request.data) is unsafe; huge_tree=True removes the limits"


def describe():
    # parser = etree.XMLParser(huge_tree=True)
    return HELP
