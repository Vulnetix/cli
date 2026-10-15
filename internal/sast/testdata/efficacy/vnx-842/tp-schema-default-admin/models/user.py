from django.db import models
from sqlalchemy import Boolean, Column, Integer, String

from .base import Base


class Member(models.Model):
    name = models.CharField(max_length=80)
~>    role = models.CharField(max_length=20, default="admin")
~>    is_staff = models.BooleanField(default=True)


class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
~>    access_level = Column(String(20), default='superuser')
~>    is_admin = Column(Boolean, default=True, nullable=False)
