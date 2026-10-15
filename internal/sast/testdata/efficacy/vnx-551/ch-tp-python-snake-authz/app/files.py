import os

from flask import Flask, abort, request, send_file

app = Flask(__name__)
ROOT = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("name", "")
~>    if not has_permission(current_user(), name):
        abort(403)
    real = os.path.realpath(os.path.join(ROOT, name))
    return send_file(real)


@app.route("/raw/<path:sub>")
def raw(sub):
    p = request.path
~>    if p == "/raw/secret.txt":
        abort(403)
    from urllib.parse import unquote
    p = unquote(p)
    return send_file(os.path.join(ROOT, p.lstrip("/")))
