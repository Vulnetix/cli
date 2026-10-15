from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
~>    role = Column(String(32), default="admin")
    active = Column(Boolean, default=True)
