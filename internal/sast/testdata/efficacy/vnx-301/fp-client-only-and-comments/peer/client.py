import hashlib
import hmac


def respond(challenge):
    # return hmac.new(KEY, challenge, hashlib.sha256).digest() and compare_digest on the server
    return hmac.new(KEY, challenge, hashlib.sha256).digest()
