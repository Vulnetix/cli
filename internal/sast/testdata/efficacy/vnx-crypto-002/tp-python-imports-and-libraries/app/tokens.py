import hashlib as hl
from hashlib import sha1, sha256
from hashlib import sha1 as legacy_hash

from Crypto.Hash import SHA1, SHA
from cryptography.hazmat.primitives import hashes


def api_token(user_id, secret):
~>    return sha1(f"{secret}:{user_id}".encode()).hexdigest()


def reset_code(email):
~>    return legacy_hash(email.encode()).hexdigest()[:8]


def aliased(blob):
~>    return hl.sha1(blob).hexdigest()


def pycryptodome(blob):
~>    return SHA1.new(blob).hexdigest()


def pycrypto_legacy_module(blob):
~>    return SHA.new(blob).hexdigest()


def cryptography_digest(blob):
~>    d = hashes.Hash(hashes.SHA1())
    d.update(blob)
    return d.finalize()


def strong(blob):
    return sha256(blob).hexdigest()
