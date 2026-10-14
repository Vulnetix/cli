import hashlib as hl
from hashlib import md5, sha256
from hashlib import md5 as weak_digest

from Crypto.Hash import MD5
from cryptography.hazmat.primitives import hashes


def hash_password(password):
~>    return md5(password.encode()).hexdigest()


def api_key_fingerprint(api_key):
~>    return weak_digest(api_key.encode()).hexdigest()


def module_alias(blob):
~>    return hl.md5(blob).hexdigest()


def pycryptodome_digest(blob):
~>    h = MD5.new(blob)
    return h.hexdigest()


def cryptography_digest(blob):
~>    digest = hashes.Hash(hashes.MD5())
    digest.update(blob)
    return digest.finalize()


def strong(blob):
    return sha256(blob).hexdigest()
