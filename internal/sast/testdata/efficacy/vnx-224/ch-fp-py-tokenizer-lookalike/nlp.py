import base64
import logging

logger = logging.getLogger(__name__)


def debug_encoding(tokenizer_output: bytes) -> None:
    logger.debug("tokenizer output: %s", base64.b64encode(tokenizer_output))
