import bcrypt
from flask import abort, request

from .models import User


def login():
    user = User.query.filter_by(email=request.form["email"]).first()
~>    if user is None:
        abort(401)
    if not bcrypt.checkpw(request.form["password"].encode(), user.password_hash):
        abort(401)
    return start_session(user)
