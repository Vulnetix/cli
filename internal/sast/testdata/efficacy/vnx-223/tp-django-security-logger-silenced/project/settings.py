LOGGING = {
    "version": 1,
    "handlers": {
        "null": {"class": "logging.NullHandler"},
        "console": {"class": "logging.StreamHandler"},
    },
    "loggers": {
~>        "django.security.DisallowedHost": {
            "handlers": ["null"],
            "propagate": False,
        },
~>        'django.security': {'handlers': [], 'propagate': False},
    },
}
