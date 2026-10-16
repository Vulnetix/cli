import hashlib
import hmac


def legacy_mac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.md5).hexdigest()


def cache_bucket(url: str) -> str:
    return hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
