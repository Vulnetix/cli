import os

SECRET_KEY = os.environ["SECRET_KEY"]
DEBUG = False
~>ALLOWED_HOSTS = ['*']
~>CSRF_TRUSTED_ORIGINS = ["*"]
