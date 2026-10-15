from flask import request, abort


def dashboard():
~>    role = request.cookies.get("role", "user")
    if role != "admin":
        abort(403)
    return "secret"
