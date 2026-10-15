import os


class Config:
    SECRET_KEY = os.environ["SECRET_KEY"]
~>    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]


class ProductionConfig(Config):
~>    WTF_CSRF_CHECK_DEFAULT = False
