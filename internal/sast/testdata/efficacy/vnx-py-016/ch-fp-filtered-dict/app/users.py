from flask import Flask, request

from .models import User, db

app = Flask(__name__)
EDITABLE = {"name", "email", "bio"}


@app.post("/users")
def create_user():
    data = {k: v for k, v in request.get_json().items() if k in EDITABLE}
    user = User(**data)
    db.session.add(user)
    db.session.commit()
    return {"id": user.id}
