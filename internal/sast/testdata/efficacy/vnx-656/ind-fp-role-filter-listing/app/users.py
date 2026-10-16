from flask import request


def list_users():
    users = User.query
    if request.args.get("role") == "admin":
        users = users.filter_by(role="admin")
    return users.all()
