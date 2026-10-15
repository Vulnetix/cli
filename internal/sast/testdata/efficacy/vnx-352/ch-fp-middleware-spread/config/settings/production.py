from .base import *  # noqa: F401,F403
from .base import BASE_MIDDLEWARE

MIDDLEWARE = [
    "django.middleware.gzip.GZipMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    *BASE_MIDDLEWARE,
]
