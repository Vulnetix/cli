import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
~>DEBUG = bool(os.environ.get("DJANGO_DEBUG"))
~>ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", False)
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "localhost").split(",")
