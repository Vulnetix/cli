import os

SECRET_KEY = os.environ["SECRET_KEY"]
~>DEBUG = os.environ.get("DEBUG", True)
ALLOWED_HOSTS = ["*"]
INSTALLED_APPS = ["django.contrib.contenttypes", "rest_framework"]
ROOT_URLCONF = "api.urls"
