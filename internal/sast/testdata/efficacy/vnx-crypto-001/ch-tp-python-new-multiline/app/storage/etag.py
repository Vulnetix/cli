import hashlib
from hashlib import md5 as _weak


def legacy_signature(payload: bytes) -> str:
    h = hashlib.new("md5")
    h.update(payload)
    return h.hexdigest()


def fingerprint(blob):
~>    return hashlib.md5(
        blob
    ).hexdigest()


def token_for(user_id):
~>    return _weak(str(user_id).encode()).hexdigest()
