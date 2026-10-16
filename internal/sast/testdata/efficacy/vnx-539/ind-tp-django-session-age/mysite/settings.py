import os

DEBUG = False
ALLOWED_HOSTS = ["example.com"]

SESSION_ENGINE = "django.contrib.sessions.backends.db"
~>SESSION_COOKIE_AGE = 60 * 60 * 24 * 365
SESSION_COOKIE_SECURE = True
