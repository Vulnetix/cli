import logging

logging.disable(logging.NOTSET)

LOGGING = {
    "version": 1,
    "loggers": {
        "django.security": {"handlers": ["console", "mail_admins"], "propagate": False},
        "django.db.backends": {"handlers": ["null"], "propagate": False},
    },
}
# "django.security.DisallowedHost": {"handlers": ["null"], "propagate": False},
