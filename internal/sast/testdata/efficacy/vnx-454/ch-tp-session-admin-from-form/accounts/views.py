from flask import Blueprint, redirect, request, session

bp = Blueprint("accounts", __name__)


@bp.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    if user is None:
        return redirect("/login?failed=1")
    session["user_id"] = user.id
~>    session["is_admin"] = request.form.get("is_admin") == "on"
    return redirect("/dashboard")
