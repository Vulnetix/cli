from flask import request

from .models import db, User


def register():
    data = request.get_json()
    user = User(email=data["email"])
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()
    if user.password == request.form.get("password"):
        return "same"
    return "ok"
