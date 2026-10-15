import hashlib
from cryptography.hazmat.primitives import hashes


def sign(body):
~>    h = hashlib.new('sha1', body)
    return h.hexdigest()


def digest_obj():
~>    return hashes.Hash(hashes.SHA1())


def checksum(data):
~>    return hashlib.sha1(
        data
    ).hexdigest()
