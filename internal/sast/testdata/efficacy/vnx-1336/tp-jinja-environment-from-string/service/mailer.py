import jinja2
from jinja2 import Environment, BaseLoader
from flask import request

env = Environment(loader=BaseLoader())


def render_mail():
    data = request.get_json()
~>    tpl = env.from_string(data["body"])
    return tpl.render(user="x")


def render_subject():
    src = request.values.get("subject")
~>    return jinja2.Template(src).render()
