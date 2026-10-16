from flask import request
from mako.template import Template


def page():
~>    return Template(request.data.decode()).render()
