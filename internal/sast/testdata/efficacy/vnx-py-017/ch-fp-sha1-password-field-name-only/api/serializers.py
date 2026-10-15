import hashlib


def fingerprint(payload):
    fields = sorted(k for k in payload if k != "password")
    return hashlib.sha1(",".join(fields).encode()).hexdigest()
