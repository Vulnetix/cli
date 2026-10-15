import logging

log = logging.getLogger(__name__)


def handle(err):
    log.warning("failed with %s", type(err).__name__)
    label = f"{type(err).__name__}: {err}"
    if type(err) is ValueError:
        return label
    if handler.__name__ == "default_handler":
        return None
    return label


if __name__ == "__main__":
    handle(Exception("x"))
