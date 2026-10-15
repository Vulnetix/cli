DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "app",
    },
}

SECURITY = {
    "session_cookie_secure": True,
    "csrf_cookie_secure": True,
    "hsts_seconds": 31536000,
~>    "session_cookie_secure": False,
}
