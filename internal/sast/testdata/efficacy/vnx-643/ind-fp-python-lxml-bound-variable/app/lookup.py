from flask import request, jsonify
from lxml import etree

TREE = etree.parse("data/users.xml")


def lookup():
    user = request.args.get("name", "")
    rows = TREE.xpath("//user[@name=$name]", name=user)
    find_by_id = etree.XPath("//user[@id=$uid]")
    more = find_by_id(TREE, uid=request.args.get("id", ""))
    return jsonify({"count": len(rows) + len(more)})
