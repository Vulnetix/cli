from flask import request
from lxml import etree

TREE = etree.parse("users.xml")


def default_name(requested):
    names = NameBook.standard()
    chosen = names.entry("default")
    return chosen


def lookup():
    name = request.args.get("name", "")
    who = default_name(name)
    return TREE.xpath(f"//user[@name='{who}']")


def staff():
    dept = request.args.get("dept", "")
    book = DeptBook.standard()
    code = book.code_of("staff")
    return TREE.xpath("//user[@dept='" + code + "']")
