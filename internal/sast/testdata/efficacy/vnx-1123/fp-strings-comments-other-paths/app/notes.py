import logging

log = logging.getLogger(__name__)

# with open(__file__, "w") as fh:  (never do this)
WARNING = "fn.__code__ = other.__code__ is self-modifying"


def save(path, text):
    log.info("not calling open(__file__, 'w')")
    with open(path, "w") as fh:
        fh.write(text)
