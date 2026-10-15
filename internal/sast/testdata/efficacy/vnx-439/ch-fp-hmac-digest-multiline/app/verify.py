import hashlib
import hmac


def verify(key, msg, sig):
    expected = hmac.new(
        key,
        msg,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


def quick(key, msg):
    return hmac.digest(key, msg, "sha256")


def strong(key, msg):
    return hmac.HMAC(key, msg, hashlib.sha512).digest()


def positional(key, msg):
    return hmac.new(key, msg,
                    hashlib.sha384).hexdigest()
