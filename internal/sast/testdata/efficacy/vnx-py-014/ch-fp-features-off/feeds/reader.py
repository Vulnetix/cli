import xml.sax
from xml.sax.handler import feature_external_ges, feature_namespaces


def read(stream, handler):
    parser = xml.sax.make_parser()
    parser.setFeature(feature_external_ges, False)
    parser.setFeature(feature_namespaces, True)
    parser.setContentHandler(handler)
    parser.parse(stream)
