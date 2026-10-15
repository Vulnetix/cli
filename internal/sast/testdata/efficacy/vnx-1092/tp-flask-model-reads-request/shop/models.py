from datetime import datetime

~>from flask import request, g
from sqlalchemy import Column, Integer, String

from .db import Base


class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    note = Column(String)

    @classmethod
    def from_form(cls):
~>        note = request.form.get("note", "")
        return cls(note=note)

    @classmethod
    def page(cls):
~>        size = int(request.args.get("size", 50))
        return g.db.query(cls).limit(size).all()
