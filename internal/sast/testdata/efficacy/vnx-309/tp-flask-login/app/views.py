from flask import request, session, redirect

from .models import User


def login():
    u = User.query.filter_by(username=request.form["username"]).first()
~>    if u and u.password == request.form["password"]:
        session["uid"] = u.id
        return redirect("/")
~>    elif u and u.password != request.form["password"]:
        return "bad password", 401
