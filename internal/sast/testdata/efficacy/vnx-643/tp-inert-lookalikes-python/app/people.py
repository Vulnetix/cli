from flask import request
from lxml import etree

TREE = etree.parse("people.xml")


def pick_name(requested):
    names = NameBook.standard()
    chosen = names.entry(requested)
    return chosen


def lookup():
    name = request.args.get("name", "")
    who = pick_name(name)
~>    return TREE.xpath(f"//user[@name='{who}']")


def staff():
    dept = request.args.get("dept", "")
    book = DeptBook.standard()
    code = book.code_of(dept)
~>    return TREE.xpath("//user[@dept='" + code + "']")


def scoped():
    book = DeptBook(request.args.get("scope", ""))
    code = book.code_of("staff")
~>    return TREE.xpath("//user[@dept='" + code + "']")
