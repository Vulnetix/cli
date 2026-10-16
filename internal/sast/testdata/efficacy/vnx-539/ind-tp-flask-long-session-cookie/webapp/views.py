from flask import Blueprint, make_response, redirect, request

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    resp = make_response(redirect("/"))
~>    resp.set_cookie("session_token", user.issue_token(), max_age=7776000, httponly=True)
    return resp
