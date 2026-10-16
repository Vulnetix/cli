import base64
from flask import request


def current_user():
    session_token = request.cookies.get("session")
~>    username = base64.b64decode(session_token).decode().split(":")[0]
    return User.query.filter_by(name=username).first()
