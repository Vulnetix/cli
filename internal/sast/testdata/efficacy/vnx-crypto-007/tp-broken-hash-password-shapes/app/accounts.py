import hashlib
from hashlib import md5


def store(user, password):
~>    user.password_hash = md5(password.encode()).hexdigest()


def store_salted(user, password, salt):
~>    user.password_hash = hashlib.md5((salt + password).encode("utf-8")).hexdigest()
