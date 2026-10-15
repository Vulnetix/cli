import logging
import os

logger = logging.getLogger("svc")


def boot():
~>    logger.info("starting with environment %s", os.environ)
~>    logger.debug(f"env={dict(os.environ)}")
