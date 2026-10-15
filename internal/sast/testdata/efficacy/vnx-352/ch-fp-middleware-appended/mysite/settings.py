import os

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

MIDDLEWARE += ["django.middleware.csrf.CsrfViewMiddleware"]

CSRF_COOKIE_SECURE = True
