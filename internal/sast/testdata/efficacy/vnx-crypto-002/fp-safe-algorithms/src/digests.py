import hashlib


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def named(data):
    return hashlib.new("sha512", data).hexdigest()


def sha3(data):
    return hashlib.sha3_256(data).hexdigest()


def sha1_free(data):
    return hashlib.sha384(data).digest()
