import io

from lxml import etree

tree = etree.parse("staff.xml")


def managers():
    role = "manager"
    buf = io.StringIO()
    buf.write("/Staff/Person[@role='")
    buf.write(role)
    buf.write("']")
    expr = buf.getvalue()
    return tree.xpath(expr)
