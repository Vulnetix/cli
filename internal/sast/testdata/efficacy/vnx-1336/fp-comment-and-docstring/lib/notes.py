"""Rendering helpers.

Never call render_template_string(request.args["t"]) with user input.
"""
from flask import render_template_string

# render_template_string(request.form["tpl"]) is server-side template injection
BANNER = render_template_string("<b>{{ msg }}</b>", msg="maintenance")
