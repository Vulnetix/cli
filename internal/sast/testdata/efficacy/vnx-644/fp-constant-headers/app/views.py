from flask import request, make_response


def page():
    resp = make_response("ok")
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Request-Id"] = str(uuid4())
    if request.args.get("debug"):
        resp.headers["X-Debug"] = "1"
    return resp
