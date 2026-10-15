import string
from string import Template

from flask import request


def greet():
    pattern = request.args.get("fmt", "Hello $name")
    a = string.Template(pattern).safe_substitute(name="x")
    b = Template(pattern).safe_substitute(name="y")
    return a + b
