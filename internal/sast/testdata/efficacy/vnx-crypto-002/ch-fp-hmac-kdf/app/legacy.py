import hashlib
import hmac


def totp_mac(key, counter):
    return hmac.new(key, counter, hashlib.sha1).digest()


def derive(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw, salt, 600_000)
