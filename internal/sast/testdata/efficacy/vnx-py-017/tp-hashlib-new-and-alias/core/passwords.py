import hashlib as hl


def digest(password):
~>    return hl.new('SHA1', password.encode()).hexdigest()


def digest_md5(pwd):
~>    return hl.md5(
        pwd.encode("utf-8")
    ).hexdigest()
