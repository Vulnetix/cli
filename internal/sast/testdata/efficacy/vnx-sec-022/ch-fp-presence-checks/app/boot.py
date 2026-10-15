import logging

logger = logging.getLogger(__name__)


def report(password, api_key):
    logger.info("password set: %s", password is not None)
    logger.info("api key: %s", "set" if api_key else "unset")
    logger.info("token endpoint %s", token_url)
