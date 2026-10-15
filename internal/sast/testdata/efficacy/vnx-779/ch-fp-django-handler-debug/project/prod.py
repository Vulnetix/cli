DEBUG = False
LOGGING = {
    "version": 1,
    "root": {
        "handlers": ["console"],
        "level": "DEBUG" if DEBUG else "WARNING",
    },
}
