import xml.dom.minidom
import xml.sax
import xml.sax.handler
from xml.dom.pulldom import parseString
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges, feature_external_pes


def upload(request):
    parser = make_parser()
~>    parser.setFeature(feature_external_ges, True)
    doc = parseString(request.body.decode("utf-8"), parser=parser)
    return doc


def report(data):
    p = xml.sax.make_parser()
~>    p.setFeature(xml.sax.handler.feature_external_ges, True)
~>    p.setFeature(feature_external_pes, 1)
~>    p.setFeature("http://xml.org/sax/features/external-general-entities", True)
    return xml.dom.minidom.parseString(data, p)
