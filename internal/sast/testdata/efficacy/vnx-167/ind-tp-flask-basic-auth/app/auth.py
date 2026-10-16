import base64

from flask import abort, request

from .models import User


def current_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        abort(401)
    decoded = base64.b64decode(header[6:]).decode("utf-8")
~>    username, password = decoded.split(":")
    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        abort(401)
    return user
