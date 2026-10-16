import hashlib

from flask import request

from .models import User, db


def signup():
    form = request.form
    digest = hashlib.sha512(form["new_password"].encode("utf-8")).hexdigest()
    db.session.add(User(name=form["name"], password_hash=digest))
    db.session.commit()


def change_password(user):
    secret = request.json.get("password")
~>    user.password_hash = hashlib.sha1(secret.encode()).hexdigest()
    db.session.commit()
