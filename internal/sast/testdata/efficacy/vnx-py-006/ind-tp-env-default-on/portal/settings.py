import os

INSTALLED_APPS = ["django.contrib.admin", "django.contrib.auth"]
MIDDLEWARE = ["django.middleware.common.CommonMiddleware"]
ROOT_URLCONF = "portal.urls"
SECRET_KEY = os.environ.get("SECRET_KEY", "x")
~>DEBUG = os.environ.get("DJANGO_DEBUG", True)
