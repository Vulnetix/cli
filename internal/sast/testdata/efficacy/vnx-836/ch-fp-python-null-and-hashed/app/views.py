from flask import redirect, request

from .security import hash_password
from .models import User


def login():
    user = User.query.filter_by(email=request.form["email"]).first()
    if user.password_hash is None or request.form.get("reset") == "1":
        return redirect("/reset")
    candidate = hash_password(request.form["password"], user.salt)
    if candidate == user.password_hash:
        return redirect("/home")
    return redirect("/login")
