import xml.dom.minidom
import xml.etree.ElementTree as etree
import xml.sax
from xml.sax.handler import feature_external_ges

import defusedxml.ElementTree as DET
from flask import request


def feed():
    a = etree.fromstring(request.data)
    b = etree.parse("feeds/rss.xml")
    c = xml.dom.minidom.parseString(request.data)
    p = xml.sax.make_parser()
    p.setFeature(feature_external_ges, False)
    d = DET.fromstring(request.data)
    return a, b, c, d
