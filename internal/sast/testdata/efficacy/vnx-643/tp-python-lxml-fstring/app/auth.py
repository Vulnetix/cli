from flask import request
from lxml import etree

tree = etree.parse("users.xml")


def login():
    user = request.form["user"]
    pw = request.form["password"]
~>    match = tree.xpath(f"//user[@name='{user}' and @password='{pw}']")
~>    rows = tree.getroot().xpath("//user[@name='" + user + "']/email/text()")
~>    found = tree.xpath(
        "//user[@id='%s']" % request.args.get("id")
    )
    return bool(match or rows or found)
