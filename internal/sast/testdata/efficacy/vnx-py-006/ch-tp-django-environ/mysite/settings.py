import environ

env = environ.Env()

SECRET_KEY = env("SECRET_KEY")
~>DEBUG = env.bool("DEBUG", default=True)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
]
ROOT_URLCONF = "mysite.urls"
