LOGGING = {
    "version": 1,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
        "file": {"class": "logging.FileHandler", "filename": "app.log"},
~>        "console": {"class": "logging.NullHandler"},
    },
    "root": {"handlers": ["console", "file"], "level": "INFO"},
}
