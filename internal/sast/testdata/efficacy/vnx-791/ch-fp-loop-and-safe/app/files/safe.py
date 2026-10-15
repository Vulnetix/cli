import os
import bleach

BASE = "/srv/data"


def sanitize(name):
    previous = None
    while previous != name:
        previous = name
        name = name.replace("../", "")
    return name


def resolve(name):
    full = os.path.realpath(os.path.join(BASE, name))
    if not full.startswith(BASE + os.sep):
        raise ValueError("outside base")
    return full


def clean_html(html):
    return bleach.clean(html, tags=[], strip=True)
