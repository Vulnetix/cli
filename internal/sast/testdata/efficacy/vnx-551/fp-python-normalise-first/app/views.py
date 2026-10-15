import os
from urllib.parse import unquote

from flask import Flask, abort, request, send_file

app = Flask(__name__)
ROOT = "/srv/reports"


@app.route("/report")
def report():
    name = unquote(request.args.get("name", ""))
    target = os.path.realpath(os.path.join(ROOT, name))
    if not has_permission(current_user(), target):
        abort(403)
    return send_file(target)


@app.route("/other")
def other():
    p = request.path
    if p.startswith("/admin"):
        abort(403)
    title = unquote(request.args.get("title", ""))
    return title
