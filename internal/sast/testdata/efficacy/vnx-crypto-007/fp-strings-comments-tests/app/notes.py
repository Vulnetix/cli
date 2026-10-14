import hashlib

# never do hashlib.md5(password.encode()) for storage
WARNING = "hashlib.sha256(password) is not a password hash"


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()
