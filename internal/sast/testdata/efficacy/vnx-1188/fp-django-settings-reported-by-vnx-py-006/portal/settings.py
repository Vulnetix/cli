import os

SECRET_KEY = os.environ["PORTAL_SECRET_KEY"]
DEBUG = os.environ.get("DEBUG", True)
ALLOWED_HOSTS = ["portal.example.org"]
