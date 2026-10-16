from .base import *  # noqa: F401,F403

DEBUG = False
ALLOWED_HOSTS = ["shop.example.com"]

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_HTTPONLY = True
~>SESSION_COOKIE_SECURE = False
~>CSRF_COOKIE_SECURE   = False
SESSION_COOKIE_AGE = 60 * 60 * 8

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "shop",
    }
}
