import logging, hashlib
log = logging.getLogger(__name__)

def f(password, token, api_key):
    log.info("Authenticating user")
    log.info("password has been set: %s", bool(password))
    log.debug("token present: %s", token is not None)
    log.info("api key sha: %s", hashlib.sha256(api_key.encode()).hexdigest())
    log.info("password policy requires 12 characters")
