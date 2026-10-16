from flask import request
from mako.template import Template


def render_invoice_footer(invoice):
    footer = request.form["footer"]
~>    tmpl = Template(footer)
    return tmpl.render(invoice=invoice)
