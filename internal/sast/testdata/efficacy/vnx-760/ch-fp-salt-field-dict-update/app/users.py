import hashlib
import os

SALT_FIELD = "salt"
HASH_FIELD = "hash"


def make_record(name: str, password: str) -> dict:
    salt = os.urandom(16)
    record = {"name": name}
    record.update({SALT_FIELD: salt.hex()})
    record.update({HASH_FIELD: hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()})
    return record
