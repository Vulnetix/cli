import base64
import hashlib
import logging

log = logging.getLogger("audit")


def record_token_use(token: bytes) -> None:
    log.info("token fingerprint %s", base64.b64encode(hashlib.sha256(token).digest()))
