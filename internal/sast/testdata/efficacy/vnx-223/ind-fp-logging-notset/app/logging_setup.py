import logging


def configure(quiet=False):
    logging.disable(logging.NOTSET)
    logging.getLogger("urllib3").disabled = True
    if quiet:
        logging.getLogger("app.metrics").setLevel(logging.WARNING)
