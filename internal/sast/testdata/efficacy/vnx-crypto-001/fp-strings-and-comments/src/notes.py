import hashlib

# hashlib.md5(password) was the legacy scheme
LEGACY = "hashlib.md5(password).hexdigest()"


def current(password, salt):
    return hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1)  # was hashlib.md5(password)
