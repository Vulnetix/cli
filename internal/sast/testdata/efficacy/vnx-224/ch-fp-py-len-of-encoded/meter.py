import base64
import logging

logger = logging.getLogger(__name__)


def meter(api_key: str) -> None:
    logger.info("encoded key size %d", len(base64.b64encode(api_key.encode())))
