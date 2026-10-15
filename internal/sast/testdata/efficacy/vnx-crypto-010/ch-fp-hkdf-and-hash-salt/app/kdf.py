import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def subkey(master):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"app-context-v1", info=b"enc").derive(master)


def cache_key(value):
    return hashlib.blake2b(value, salt=b"cachekey", digest_size=16).hexdigest()
