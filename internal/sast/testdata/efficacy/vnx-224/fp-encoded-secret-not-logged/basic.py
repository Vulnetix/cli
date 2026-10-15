import base64
import logging

logger = logging.getLogger(__name__)


def basic_auth_header(user, password):
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    logger.info("built basic auth header for %s", user)
    return {"Authorization": "Basic " + creds}
