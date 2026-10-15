import hashlib as hl


def signed(secret, uid):
~>    return hl.sha1((secret + uid).encode()).hexdigest()
