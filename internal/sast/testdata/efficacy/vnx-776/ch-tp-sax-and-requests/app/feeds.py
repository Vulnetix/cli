import xml.sax
import xml.etree.ElementTree as ET

import requests


def fetch(url, handler):
    resp = requests.get(url, timeout=10)
~>    root = ET.fromstring(resp.content)
    return root


def sax_upload(request, handler):
~>    xml.sax.parseString(request.data, handler)
