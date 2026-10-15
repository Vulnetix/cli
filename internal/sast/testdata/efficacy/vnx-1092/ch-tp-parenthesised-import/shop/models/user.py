~>from flask import (
    current_app,
    request,
)

from shop.db import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    @classmethod
    def from_form(cls):
~>        return cls(name=request.form["name"])
