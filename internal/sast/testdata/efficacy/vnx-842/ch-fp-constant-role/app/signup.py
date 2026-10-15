from flask import request
from .models import db, User


def register():
    data = request.get_json()
    user = User(email=data["email"], role="viewer")
    user.is_admin = False
    db.session.add(user)
    db.session.commit()
    return {"id": user.id}
