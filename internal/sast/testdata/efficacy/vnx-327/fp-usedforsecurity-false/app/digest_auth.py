import hashlib


def nonce_hash(x):
    return hashlib.md5(x, usedforsecurity=False).hexdigest()


def cnonce(s):
    cnonce = hashlib.sha1(s, usedforsecurity=False).hexdigest()[:16]
    return cnonce
