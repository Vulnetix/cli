from flask import request, session, redirect
from werkzeug.security import check_password_hash

from .models import User


def login():
    username = request.form["username"]
    user = User.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password_hash, request.form["password"]):
        return "invalid", 401
    session["user_id"] = user.id
    session["csrf"] = make_token()
    return redirect("/")
