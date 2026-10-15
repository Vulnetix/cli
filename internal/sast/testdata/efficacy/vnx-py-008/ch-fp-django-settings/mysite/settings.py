from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEBUG = True
INSTALLED_APPS = ["django.contrib.auth"]
ROOT_URLCONF = "mysite.urls"
