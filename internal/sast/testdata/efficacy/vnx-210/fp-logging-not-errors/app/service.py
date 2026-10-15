import logging

log = logging.getLogger(__name__)


def rotate(token):
    log.debug("rotating")
    try:
        store.rotate(token)
    except KeyError as exc:
        raise RuntimeError("token rotation failed") from exc
