import hashlib as hl


def signed_id(secret, uid):
~>    return hl.md5(f"{secret}:{uid}".encode()).hexdigest()
