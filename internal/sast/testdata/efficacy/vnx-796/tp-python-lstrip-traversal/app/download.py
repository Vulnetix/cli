import os
from flask import request, send_file

BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name", "")
~>    name = name.lstrip("./")
    return send_file(os.path.join(BASE, name))


def other(name):
~>    return os.path.join(BASE, name.strip('../\\'))
