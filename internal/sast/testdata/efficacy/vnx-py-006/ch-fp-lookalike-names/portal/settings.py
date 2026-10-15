import os

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
SQL_DEBUG = True
DEBUG_TOOLBAR_ENABLED = True
THUMBNAIL_DEBUG = True
INSTALLED_APPS = ["django.contrib.auth"]
ROOT_URLCONF = "portal.urls"
