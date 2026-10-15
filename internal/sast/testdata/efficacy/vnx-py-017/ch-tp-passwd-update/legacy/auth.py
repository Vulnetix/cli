import hashlib


def legacy_hash(passwd, salt):
    h = hashlib.md5()
    h.update(salt.encode())
~>    h.update(passwd.encode())
    return h.hexdigest()
