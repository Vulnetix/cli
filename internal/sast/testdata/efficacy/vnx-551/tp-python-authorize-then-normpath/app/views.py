import os

from flask import Flask, abort, request, send_file

app = Flask(__name__)
ROOT = "/srv/reports"


@app.route("/report")
def report():
    name = request.args.get("name", "")
~>    if not has_permission(current_user(), name):
        abort(403)
    target = os.path.normpath(os.path.join(ROOT, name))
    return send_file(target)


@app.route("/page")
def page():
    p = request.path
~>    if p == "/internal/metrics":
        abort(403)
    parsed = urlparse(p)
    return parsed.path
