import hashlib
import hmac


def sign(key, msg):
    return hmac.new(key, msg, hashlib.md5).hexdigest()


def sign_named(key, msg):
    return hmac.new(key, msg, digestmod="md5").hexdigest()
