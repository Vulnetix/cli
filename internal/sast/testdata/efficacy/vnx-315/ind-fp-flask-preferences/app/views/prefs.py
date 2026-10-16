from flask import make_response, request


def save_prefs():
    resp = make_response("saved")
    resp.set_cookie("locale", request.form.get("locale", "en"), samesite="Lax")
    resp.set_cookie("auth_token", request.form["token"], httponly=True, secure=True)
    # Never do: resp.set_cookie("password", request.form["password"])
    return resp
