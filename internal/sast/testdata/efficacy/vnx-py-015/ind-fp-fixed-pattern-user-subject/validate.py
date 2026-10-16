import re
from flask import request

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$")


def check():
    email = request.form["email"]
    m = re.match(r"^\d{3}-\d{4}$", request.args.get("phone", ""))
    return EMAIL.match(email), m
