from pathlib import Path
from flask import Flask, request, abort, send_file

app = Flask(__name__)
UPLOADS = Path("/srv/uploads")
ROOT = "/srv/reports/"


@app.get("/upload")
def upload():
    target = UPLOADS / request.args["name"]
~>    if not target.is_relative_to(UPLOADS):
        abort(403)
    return send_file(target)


@app.get("/report")
def report():
    full = ROOT + request.args["file"]
~>    if not full.startswith(ROOT):
        abort(403)
    return send_file(full)
