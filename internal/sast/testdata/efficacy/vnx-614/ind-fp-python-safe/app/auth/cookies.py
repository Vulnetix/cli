import os

from flask import current_app, make_response

COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"

DEFAULT_CONFIG = {
    "SESSION_COOKIE_SECURE": False,
    "SESSION_COOKIE_HTTPONLY": True,
}


def login_response(token):
    resp = make_response("", 204)
    resp.set_cookie("auth_token", token, httponly=True, secure=True, samesite="Strict")
    resp.set_cookie(
        "session_id",
        token,
        httponly=True,
        secure=COOKIE_SECURE,
    )
    resp.set_cookie("csrf_token", token, secure=current_app.config["SESSION_COOKIE_SECURE"])
    resp.set_cookie("language", "en-GB")
    resp.set_cookie("theme", "dark", max_age=3600)
    return resp


def logout_response():
    resp = make_response("", 204)
    resp.set_cookie("auth_token", "", max_age=0)
    resp.set_cookie("session_id", "", expires=0)
    resp.delete_cookie("refresh_token")
    return resp
