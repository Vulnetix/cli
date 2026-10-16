from flask import redirect, request, session, url_for

from app.models import User


def login():
    u = User.query.filter_by(email=request.form["email"]).first()
~>    if u and u.password == request.form["password"]:
        session["uid"] = u.id
        return redirect(url_for("home"))
    return "invalid credentials", 401
