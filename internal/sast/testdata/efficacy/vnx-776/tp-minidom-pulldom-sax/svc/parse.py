from xml.dom import minidom, pulldom
import xml.sax
from urllib.request import urlopen


def dom_from_request(request):
~>    dom = minidom.parseString(request.body)
    return dom.documentElement


def events(request):
    body = request.get_data()
~>    for event, node in pulldom.parseString(body):
        yield event


def sax_remote(handler, url):
~>    xml.sax.parse(urlopen(url), handler)
