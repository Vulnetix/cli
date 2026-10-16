from flask import make_response

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True


def login(token):
    resp = make_response("ok")
    resp.set_cookie("session_token", token, secure=True, httponly=True, samesite="Lax")
    return resp
