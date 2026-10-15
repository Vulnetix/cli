import logging

from itsdangerous import BadSignature

log = logging.getLogger(__name__)


def load(serializer, cookie):
    try:
        return serializer.loads(cookie)
    except BadSignature:
        log.warning("rejected session cookie with a bad signature")
        return None


def strict(serializer, cookie):
    try:
        return serializer.loads(cookie)
    except BadSignature:
        raise


logging.disable(logging.NOTSET)
