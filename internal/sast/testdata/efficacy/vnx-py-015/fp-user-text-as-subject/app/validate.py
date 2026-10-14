import re

from flask import request

EMAIL = re.compile(r"^[^@]+@[^@]+$")


def check():
    email = request.form["email"]
    ok = EMAIL.match(email)
    pin = re.match(r"^\d{4}$", request.args.get("pin", ""))
    q = request.args.get("q")
    tidy = re.sub(r"\s+", " ", q)
    words = re.findall(r"\w+", q)
    return ok, pin, tidy, words
