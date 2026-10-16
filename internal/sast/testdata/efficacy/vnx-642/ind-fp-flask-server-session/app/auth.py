from flask import Blueprint, redirect, request, session, url_for

bp = Blueprint("auth", __name__)


@bp.post("/login")
def login():
    user = check_password(request.form["email"], request.form["password"])
    if user is None:
        return redirect(url_for("auth.login_form", error=1))
    session["user_id"] = user.id
    session["role"] = user.role
    session["is_admin"] = user.is_admin
    return redirect(url_for("dashboard.home"))
