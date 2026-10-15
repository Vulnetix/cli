import os

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
~>DEBUG = bool(os.environ.get("DJANGO_DEBUG", ""))
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost").split(",")
~>SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", True)
