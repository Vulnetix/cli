from flask import request
from lxml import etree


def order():
~>    doc = etree.fromstring(f"<order><id>{request.args['id']}</id></order>")
    qty = request.form.get("qty", "1")
~>    line = "<qty>%s</qty>" % qty
    note = request.form["note"]
~>    extra = "<note>{}</note>".format(note)
    return send_to_erp(doc, line, extra)
