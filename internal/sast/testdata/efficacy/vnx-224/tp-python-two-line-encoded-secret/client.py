import base64
import logging

log = logging.getLogger("client")


def connect(api_key):
    masked = base64.b64encode(api_key.encode()).decode()
~>    log.warning("connecting with key %s", masked)
    return Session(api_key)
