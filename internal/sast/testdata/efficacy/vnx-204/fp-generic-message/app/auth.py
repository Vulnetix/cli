from flask import jsonify, request

from .models import User

INVALID = "Invalid username or password"


def login():
    user = User.query.filter_by(username=request.form["username"]).first()
    if user is None or not user.check_password(request.form["password"]):
        return jsonify(error=INVALID), 401
    return jsonify(ok=True)
