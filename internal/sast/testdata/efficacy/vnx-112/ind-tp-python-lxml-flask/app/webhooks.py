from flask import Blueprint, request
from lxml import etree
import xml.etree.ElementTree as ET

bp = Blueprint("webhooks", __name__)
PARSER = etree.XMLParser(resolve_entities=False, no_network=True)


@bp.route("/webhooks/shipment", methods=["POST"])
def shipment():
~>    root = etree.fromstring(request.data, PARSER)
    tracking = root.findtext("tracking")
    status = root.findtext("status")
    record_status(tracking, status)
    return "", 204


@bp.route("/webhooks/legacy", methods=["POST"])
def legacy():
    payload = request.get_data()
~>    doc = ET.fromstring(payload)
    return doc.findtext("id") or ""
