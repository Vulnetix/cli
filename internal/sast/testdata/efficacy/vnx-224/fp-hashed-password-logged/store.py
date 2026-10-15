import base64
import logging

logger = logging.getLogger(__name__)


def store(user, password):
    digest = hash_password(password)
    logger.info("stored credentials for %s", user.id)
    payload = base64.b64encode(user.avatar)
    logger.debug("avatar size %d", len(payload))
