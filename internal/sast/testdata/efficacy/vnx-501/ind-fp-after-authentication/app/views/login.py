from flask import redirect, request, session
from werkzeug.security import check_password_hash

from .models import User


def login():
    user = User.query.filter_by(email=request.form["email"]).first()
    if user is None or not check_password_hash(user.password_hash, request.form["password"]):
        return "invalid", 401
    session["user_id"] = user.id
    return redirect("/")
