import re

from flask import request, make_response


@app.after_request
def add_cors(resp):
    origin = request.headers.get("Origin", "")
~>    if "example.com" in origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


def is_allowed(origin):
~>    return re.match(r"https://.*\.example\.com", origin) is not None


def check_referer():
~>    if not request.headers.get("Referer", "").startswith("https://shop.example.com"):
        abort(403)
