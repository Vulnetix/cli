import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev")
    WTF_CSRF_ENABLED = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    WTF_CSRF_ENABLED = False


config = {"testing": TestingConfig}
