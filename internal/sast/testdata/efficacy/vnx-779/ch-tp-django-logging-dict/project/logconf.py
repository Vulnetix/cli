import logging.config

logging.config.dictConfig({
    "version": 1,
~>    "root": {"handlers": ["console"], "level": "DEBUG"},
})
