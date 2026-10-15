import logging

from flask import request

logger = logging.getLogger(__name__)


def audit():
    logger.info("has auth header: %s", "Authorization" in request.headers)
