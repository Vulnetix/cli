from flask import request
from werkzeug.security import check_password_hash

from .models import User


def login():
    user = User.query.filter_by(email=request.form["email"]).first()
~>    if not user:
        return "invalid credentials", 401
    if not check_password_hash(user.pw_hash, request.form["password"]):
        return "invalid credentials", 401
    return "ok"
