log.info("password hash %s", hash_password(password))
logger.debug("token %s", mask(access_token))
print("password length", len(password))
log.info("key fingerprint %s", sha256(api_key))
