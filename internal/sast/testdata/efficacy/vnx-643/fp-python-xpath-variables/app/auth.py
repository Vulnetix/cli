from flask import request
from lxml import etree

tree = etree.parse("users.xml")


def login():
    user = request.form["user"]
    match = tree.xpath("//user[@name=$name]", name=user)
    find_user = etree.XPath("//user[@name=$name]")
    return bool(match or find_user(tree, name=user))
