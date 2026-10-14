import os

DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"
TEMPLATE_DEBUG = DEBUG
INSTALLED_APPS = ["billing"]
