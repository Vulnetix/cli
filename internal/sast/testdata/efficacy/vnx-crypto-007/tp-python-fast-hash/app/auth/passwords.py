import hashlib
from hashlib import md5


def store(user, password):
~>    user.password_digest = hashlib.sha256(password.encode()).hexdigest()


def legacy(password):
~>    password = md5(password.encode()).hexdigest()
    return password


def salted(salt, raw_password):
~>    return hashlib.sha512((salt + raw_password).encode("utf-8")).hexdigest()


def incremental(pwd):
    h = hashlib.sha1()
~>    h.update(pwd.encode())
    return h.hexdigest()


def by_name(user):
~>    return hashlib.new("md5", user.password.encode()).hexdigest()
