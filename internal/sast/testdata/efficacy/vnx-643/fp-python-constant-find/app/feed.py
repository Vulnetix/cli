import xml.etree.ElementTree as ET

NS = "{http://www.w3.org/2005/Atom}"


def entries(root):
    out = []
    for entry in root.findall(NS + "entry"):
        title = entry.find(f"{NS}title")
        out.append(title.text)
    idx = "hello world".find("o" + "w")
    links = root.xpath("//a/@href")
    return out, idx, links
