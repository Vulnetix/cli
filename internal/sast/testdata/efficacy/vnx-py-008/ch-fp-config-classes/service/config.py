import os


class Config:
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY")


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = True


config = {"development": DevelopmentConfig, "testing": TestingConfig, "default": Config}
