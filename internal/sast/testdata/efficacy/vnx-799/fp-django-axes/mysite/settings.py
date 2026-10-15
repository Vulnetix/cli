INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.sessions",
    "axes",
]

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]
