import contextlib
import os
import re

from flask import request, abort

PORT = int(os.environ.get("PORT", "8000"))
WORKERS = int("4")


@app.route("/report")
def report():
    raw = request.args.get("year", "")
    if not raw.isdigit():
        abort(400)
    year = int(raw)
    week = request.args.get("week", "")
    if not re.fullmatch(r"\d{1,2}", week):
        abort(400)
    wk = int(week)
    with contextlib.suppress(TypeError, ValueError):
        top = int(request.args.get("top"))
    return build(year, wk)
