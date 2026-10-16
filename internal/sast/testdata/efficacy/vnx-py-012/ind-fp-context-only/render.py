from flask import request
from jinja2 import Template

GREETING = Template("<p>Hi {{ who }}</p>")


def page():
    who = request.args.get("who")
    return GREETING.render(who=who)
