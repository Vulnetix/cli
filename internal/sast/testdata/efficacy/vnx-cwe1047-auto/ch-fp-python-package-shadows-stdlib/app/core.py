import logging

from app.config import settings

log = logging.getLogger(__name__)


def start():
    log.info("starting with %s", settings)
