import hashlib


def store(user, password, salt):
~>    user.pw = hashlib.md5((salt + password).encode()).hexdigest()


def store2(user, pwd):
    h = hashlib.sha512()
~>    h.update(pwd.encode("utf-8"))
    user.pw = h.hexdigest()


def store3(user, password, salt):
~>    user.key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)
