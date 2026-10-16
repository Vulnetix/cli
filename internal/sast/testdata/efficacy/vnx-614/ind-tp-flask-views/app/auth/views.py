from flask import Blueprint, current_app, jsonify, make_response, request

from .tokens import issue_access_token, issue_refresh_token

bp = Blueprint("auth", __name__)


def configure(app):
~>    app.config["REMEMBER_COOKIE_SECURE"] = False
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True


@bp.post("/login")
def login():
    user = current_app.auth.verify(request.form["email"], request.form["password"])
    resp = make_response(jsonify(ok=True))
~>    resp.set_cookie("auth_token", issue_access_token(user), httponly=True, samesite="Lax")
~>    resp.set_cookie(
        "refresh_token",
        issue_refresh_token(user),
        httponly=True,
        secure=False,
        max_age=60 * 60 * 24 * 30,
    )
    resp.set_cookie("theme", "dark")
    return resp
