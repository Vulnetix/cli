import jinja2
from flask import request

env = jinja2.Environment(autoescape=True)


def preview():
    body = request.get_json()["body"]
~>    return env.from_string(body).render()


def legacy():
    src = request.form.get("src")
~>    return jinja2.Template(src).render()


def banner():
~>    return env.from_string(
        "<b>" + request.args["msg"] + "</b>"
    ).render()
