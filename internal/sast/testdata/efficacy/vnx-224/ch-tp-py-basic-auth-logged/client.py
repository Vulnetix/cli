import base64
import logging

log = logging.getLogger(__name__)


def build_headers(user, password):
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
~>    log.debug("Authorization: Basic %s", creds)
    return {"Authorization": "Basic " + creds}
