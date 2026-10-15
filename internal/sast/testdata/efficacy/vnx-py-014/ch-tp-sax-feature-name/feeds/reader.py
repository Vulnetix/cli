import xml.sax
from xml.sax.handler import feature_external_ges, feature_external_pes


def read(stream, handler):
    parser = xml.sax.make_parser()
~>    parser.setFeature(feature_external_ges, True)
~>    parser.setFeature(feature_external_pes, 1)
    parser.setContentHandler(handler)
    parser.parse(stream)
