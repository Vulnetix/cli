from flask import Flask, request
from sqlalchemy import insert

from .models import Profile, db

app = Flask(__name__)


@app.patch("/profile/<int:pid>")
def patch_profile(pid):
~>    db.session.query(Profile).filter_by(id=pid).update(request.get_json())
    db.session.commit()
    return {"ok": True}


@app.post("/profiles")
def insert_profile():
~>    db.session.execute(insert(Profile).values(**request.json))
    return {"ok": True}
