from flask import request, session
from werkzeug.security import check_password_hash

from app.models import User


def login():
    user = User.query.filter_by(email=request.form["email"]).first()
    if user and check_password_hash(user.password_hash, request.form["password"]):
        session["uid"] = user.id
        return "ok"
    return "invalid", 401
