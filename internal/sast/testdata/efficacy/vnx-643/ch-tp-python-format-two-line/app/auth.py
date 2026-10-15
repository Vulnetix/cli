from lxml import etree
from flask import request

doc = etree.parse("users.xml")


def login():
    u = request.form["username"]
    p = request.form["password"]
    query = "//account[@user='{}' and @pass='{}']".format(u, p)
~>    result = doc.getroot().xpath(query)
    return bool(result)
