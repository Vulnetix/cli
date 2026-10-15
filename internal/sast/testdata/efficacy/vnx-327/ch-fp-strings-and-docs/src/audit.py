import logging

log = logging.getLogger(__name__)

# Never store hashlib.md5(password) digests; use argon2 instead.
WARNING = "md5(password) and sha1(token) are not acceptable password hashes"


def audit(record):
    log.warning("legacy md5 password hash found for %s", record.user_id)
