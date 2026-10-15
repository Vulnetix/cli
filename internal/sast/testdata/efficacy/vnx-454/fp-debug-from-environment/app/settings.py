import os

DEBUG = os.environ.get("DEBUG", "False") == "True"
ADMIN_MODE = os.environ.get("ADMIN_MODE", "0") == "1"
SECRET_KEY = os.environ["SECRET_KEY"]
