import logging

logger = logging.getLogger(__name__)

# never do: logger.info(base64.b64encode(password.encode()))
WARNING = "logger.info(base64.b64encode(secret)) leaks the secret"


def warn():
    logger.warning(WARNING)
