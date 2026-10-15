from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    role = Column(String(32), default="member")
    is_admin = Column(Boolean, default=False)
    is_staff = Column(Boolean, nullable=False, default=False)
