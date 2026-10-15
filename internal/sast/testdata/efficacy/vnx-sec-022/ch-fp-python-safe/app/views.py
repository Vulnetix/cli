import logging

logger = logging.getLogger(__name__)


def login(request, user, password):
    logger.info("password changed for %s", user.id)
    logger.debug("masked=%s", mask(password))
    logger.info("tokens processed: %d", token_count)
    logger.info("token expires in %d seconds", token_ttl)
    logger.warning("secret %s rotated", secret_name)
    print("Password: ********")
    msg = "logger.info(password)"
    # logger.debug("pw=%s", password)
