import urllib.parse

import lxml.etree
from flask import request


def employee():
    param = urllib.parse.unquote_plus(request.cookies.get("emp", ""))
    root = lxml.etree.parse(open("employees.xml", "rb"))
    query = f'/Employees/Employee[@emplid=\'{param}\']'
~>    run_query = lxml.etree.XPath(query)
    nodes = run_query(root)
    q2 = "/Employees/Employee[@name='{}']".format(request.args["name"])
~>    more = root.xpath(q2)
    return str(nodes) + str(more)


def by_join():
    emp = request.args.get("emp", "")
    q3 = "".join(["/Employees/Employee[@emplid='", emp, "']"])
~>    return root.xpath(q3)
