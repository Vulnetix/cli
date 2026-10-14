from flask import request
from mako.template import Template


def render_snippet():
~>    return Template(request.args["t"]).render()
