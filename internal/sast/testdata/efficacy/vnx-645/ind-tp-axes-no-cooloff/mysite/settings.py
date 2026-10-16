INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "axes",
]

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

AXES_FAILURE_LIMIT = 5
~>AXES_COOLOFF_TIME = None
AXES_LOCKOUT_PARAMETERS = ["username"]
