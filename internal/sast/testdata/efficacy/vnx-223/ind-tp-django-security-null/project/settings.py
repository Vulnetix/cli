LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
        "null": {"class": "logging.NullHandler"},
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": "INFO"},
~>        "django.security.DisallowedHost": {
            "handlers": ["null"],
            "propagate": False,
        },
    },
}
