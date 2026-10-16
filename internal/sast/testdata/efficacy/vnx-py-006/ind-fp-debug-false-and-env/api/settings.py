import os

INSTALLED_APPS = ["django.contrib.admin"]
MIDDLEWARE = ["django.middleware.common.CommonMiddleware"]
ROOT_URLCONF = "api.urls"
DEBUG = os.environ.get("DEBUG", "False") == "True"
TEMPLATE_DEBUG = True
DEBUG_TOOLBAR_CONFIG = {"SHOW_TOOLBAR_CALLBACK": lambda r: True}
