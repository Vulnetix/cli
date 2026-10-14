import logging

from lxml import etree

log = logging.getLogger(__name__)

# parser.setFeature(feature_external_ges, True) re-enables XXE; never do it.
# etree.XMLParser(resolve_entities=True)
HELP = "set no_network=False only for trusted documents"


def warn():
    log.warning("someone called p.setFeature(feature_external_ges, True)")
