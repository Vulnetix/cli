import os

# DEBUG = True
# ALLOWED_HOSTS = ["*"]
# SECRET_KEY = os.environ["KEY"]
# DATABASES = {}
# CACHES = {}
# LOGGING = {}

DEBUG = False


def get(name):
    return os.environ.get(name)
