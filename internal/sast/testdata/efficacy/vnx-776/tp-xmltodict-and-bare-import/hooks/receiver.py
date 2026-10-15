import xmltodict
from xml.etree.ElementTree import fromstring, iterparse
from flask import request


def webhook():
    raw = request.get_data()
~>    msg = xmltodict.parse(raw)
~>    node = fromstring(raw)
~>    for ev, el in iterparse(request.stream):
        pass
    return msg, node
