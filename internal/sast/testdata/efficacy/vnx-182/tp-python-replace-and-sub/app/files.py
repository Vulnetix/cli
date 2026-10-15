import os
import re

from flask import request, send_file

BASE = "/srv/files"


def download():
    name = request.args.get("name", "")
~>    name = name.replace("../", "")
    return send_file(os.path.join(BASE, name))


def preview():
    raw = request.args.get("doc", "")
~>    cleaned = re.sub(r"\.\./", "", raw)
~>    cleaned = cleaned.replace('..', '', -1)
    return send_file(os.path.join(BASE, cleaned))


def comment():
    body = request.form["body"]
~>    body = re.sub("<script>", "", body, flags=re.I)
    return body
