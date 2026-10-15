from flask import request, session
from werkzeug.security import check_password_hash


def login():
    if request.form.get("action") == "login":
        user = find_user(request.form["username"])
        if user and check_password_hash(user.pw_hash, request.form["password"]):
            session["user_id"] = user.id
            return True
    return False
