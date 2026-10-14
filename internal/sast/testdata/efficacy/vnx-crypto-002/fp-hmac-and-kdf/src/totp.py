import hashlib
import hmac

import pyotp


def hotp(key, counter):
    return hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()


def derive(password, salt):
    return hashlib.pbkdf2_hmac("sha1", password, salt, 310_000)


def totp(secret):
    return pyotp.TOTP(secret, digest=hashlib.sha1).now()
