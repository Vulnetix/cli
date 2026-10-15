from xml.sax.saxutils import escape

from flask import request
from lxml import etree


def order():
    return etree.fromstring(f"<order><id>{escape(request.args['id'])}</id></order>")
