from flask import request
from lxml import etree

PING = "<ping><from>web</from></ping>"


def ping():
    user = request.args.get("user")
    doc = etree.fromstring("<ping><from>web</from></ping>")
    return doc, user, PING
