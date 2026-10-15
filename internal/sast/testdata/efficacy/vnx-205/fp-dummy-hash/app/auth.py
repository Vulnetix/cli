import bcrypt
from flask import abort, request

from .models import User

DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt())


def login():
    user = User.query.filter_by(email=request.form["email"]).first()
    if user is None:
        bcrypt.checkpw(request.form["password"].encode(), DUMMY_HASH)
        abort(401)
    if not bcrypt.checkpw(request.form["password"].encode(), user.password_hash):
        abort(401)
    return start_session(user)
