LOGGING = {
    "version": 1,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
~>            "level": "DEBUG",
        },
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}
