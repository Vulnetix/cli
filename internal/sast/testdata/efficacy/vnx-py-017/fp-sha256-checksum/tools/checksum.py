import hashlib


def hibp_prefix(password):
    return hashlib.sha256(password.encode()).hexdigest()[:5]


def checksum(data):
    m = hashlib.new("sha256")
    m.update(data)
    return m.hexdigest()
