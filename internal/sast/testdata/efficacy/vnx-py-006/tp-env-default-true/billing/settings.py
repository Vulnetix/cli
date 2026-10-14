import os

~>DEBUG = os.environ.get("DJANGO_DEBUG", True)
INSTALLED_APPS = ["billing"]
