import io

from flask import request
from lxml import etree

tree = etree.parse("staff.xml")


def by_badge():
    badge = request.args.get("badge", "")
    buf = io.StringIO()
    buf.write("/Staff/Person[@badge='")
    buf.write(badge)
    buf.write("']")
    expr = buf.getvalue()
~>    return tree.xpath(expr)
