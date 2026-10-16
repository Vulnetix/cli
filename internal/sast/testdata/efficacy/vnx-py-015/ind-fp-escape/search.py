import re
from flask import request


def find(text):
    safe = re.escape(request.args.get("q", ""))
    a = re.search(safe, text)
    b = re.search(re.escape(request.form["q"]), text)
    return a, b
