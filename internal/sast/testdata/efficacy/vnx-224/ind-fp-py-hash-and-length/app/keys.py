import base64
import hashlib
import logging

logger = logging.getLogger(__name__)


def audit_key(api_key, password):
    fingerprint = hashlib.sha256(api_key.encode()).hexdigest()[:12]
    logger.info("key fingerprint %s", fingerprint)
    logger.info("encoded password length %d", len(base64.b64encode(password.encode())))
    logger.debug("digest %s", hashlib.sha256(base64.b64encode(api_key.encode())).hexdigest())
