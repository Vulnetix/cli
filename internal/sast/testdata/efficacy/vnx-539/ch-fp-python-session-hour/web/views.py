from flask import make_response


def login(sid):
    resp = make_response("ok")
    resp.set_cookie("sessionid", sid, max_age=3600, httponly=True, secure=True)
    resp.set_cookie("theme", "dark", max_age=60 * 60 * 24 * 365)
    return resp
