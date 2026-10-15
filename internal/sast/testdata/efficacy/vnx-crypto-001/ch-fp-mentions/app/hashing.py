import hashlib

ALLOWED = {"sha256": hashlib.sha256, "sha512": hashlib.sha512}


def pick(name):
    if name == "md5":
        raise ValueError("md5 is not allowed")
    return ALLOWED[name]()
