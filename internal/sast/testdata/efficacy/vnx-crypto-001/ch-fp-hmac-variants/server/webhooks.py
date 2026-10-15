import hashlib
import hmac


def verify(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, digestmod="md5").hexdigest()
