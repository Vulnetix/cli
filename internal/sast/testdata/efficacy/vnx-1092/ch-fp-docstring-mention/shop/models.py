"""Data models.

Views read request.args and request.form and pass plain values here;
nothing in this module may import from flask import request.
"""
from flask import current_app, g
from shop.db import db


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
