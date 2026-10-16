import hashlib


~>def hash_password(raw):
    """TODO"""
    return hashlib.sha256(raw.encode()).hexdigest()
