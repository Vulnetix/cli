import hashlib
import hmac


def verify(secret, body, sig):
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not sig or not hmac.compare_digest(sig, expected):
        raise PermissionError("bad signature")
    return True


def short_id(blob):
    full = hashlib.sha1(blob).hexdigest()
    return full[:8]


def verify_checksum(data, checksum):
    if checksum is None:
        raise ValueError("checksum required")
    if checksum and hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("checksum mismatch")
