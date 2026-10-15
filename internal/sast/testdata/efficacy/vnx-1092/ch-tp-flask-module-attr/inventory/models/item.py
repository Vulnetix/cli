import flask

from inventory.db import db


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(80))

    @classmethod
    def visible(cls):
~>        owner = flask.request.cookies.get("owner")
        return cls.query.filter_by(owner=owner).all()
