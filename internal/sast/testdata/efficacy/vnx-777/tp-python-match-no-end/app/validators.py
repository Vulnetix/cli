import re


def check_username(name):
~>    if not re.match(r"[a-zA-Z0-9_]+", name):
        raise ValueError("invalid username")
    return name


def check_slug(slug):
~>    if not re.search(r'^[a-z0-9-]{3,40}', slug):
        raise ValueError("invalid slug")


def is_code(code):
~>    return re.search(r"[A-Z]{6}$", code) is not None
