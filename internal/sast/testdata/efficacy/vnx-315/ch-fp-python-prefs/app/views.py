from flask import make_response


def prefs():
    resp = make_response("ok")
    resp.set_cookie("timezone", "UTC")
    resp.set_cookie("password_hint_seen", "1")
    return resp
