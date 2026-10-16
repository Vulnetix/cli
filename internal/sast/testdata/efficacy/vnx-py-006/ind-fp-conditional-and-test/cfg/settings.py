import os

INSTALLED_APPS = ["django.contrib.admin"]
MIDDLEWARE = ["django.middleware.common.CommonMiddleware"]
ROOT_URLCONF = "cfg.urls"
DEBUG = False
if os.environ.get("ENV") == "dev":
    DEBUG = True
