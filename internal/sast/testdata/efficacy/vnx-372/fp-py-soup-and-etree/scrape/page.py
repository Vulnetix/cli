from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET


def title(html):
    soup = BeautifulSoup(html, "html.parser")
    if soup.find("title"):
        return soup.find("title").text
    return None


def version(xml):
    root = ET.fromstring(xml)
    if root.find("version") is not None:
        return root.find("version").text
    return None
