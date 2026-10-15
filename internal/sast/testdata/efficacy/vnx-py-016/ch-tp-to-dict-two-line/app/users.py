from flask import Flask, request

from .models import User, db

app = Flask(__name__)


@app.post("/signup")
def signup():
    form = request.form.to_dict()
~>    user = User(**form)
    db.session.add(user)
    db.session.commit()
    return {"id": user.id}
