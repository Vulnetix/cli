import xml.sax
from xml.sax.handler import feature_external_ges


def make():
    parser = xml.sax.make_parser()
~>    parser.setFeature(feature_external_ges, True)
    return parser
