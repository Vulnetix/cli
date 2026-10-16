from sqlalchemy import Column, Integer, String
~>from flask import request, session
from flask import g

from shop.db import Base


class Cart(Base):
    __tablename__ = "carts"
    id = Column(Integer, primary_key=True)
    owner = Column(String)

    @classmethod
    def current(cls):
~>        uid = session["user_id"]
        return g.db.query(cls).filter_by(owner=uid).first()
