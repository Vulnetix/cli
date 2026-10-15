import logging

log = logging.getLogger(__name__)


def mask(api_key: str) -> str:
    return api_key[:4] + "*" * (len(api_key) - 4)


def audit(token: str) -> None:
    log.info("issued token prefix=%s", token[:6])
