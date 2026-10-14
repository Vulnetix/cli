import os

SECRET_KEY = os.environ["SECRET_KEY"]
~>DEBUG = os.getenv("DEBUG", "True") == "True"
ROOT_URLCONF = "api.urls"
