import hashlib
import hmac


def verify_token(key, payload, provided):
    computed = hmac.new(key, payload, hashlib.sha256).hexdigest()
~>    return computed.startswith(provided)


def verify_download(data, given):
    digest = hashlib.sha256(data).hexdigest()
~>    if given in digest:
        return True
    return False


def verify_short(key, msg, tag):
~>    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:8] == tag
