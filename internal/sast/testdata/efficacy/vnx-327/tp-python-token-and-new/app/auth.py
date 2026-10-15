import hashlib
import time


def make_reset_token(email):
~>    return hashlib.md5(f"{email}:{time.time()}".encode()).hexdigest()


def hash_password(pw, salt):
~>    h = hashlib.new('sha1')
    h.update(salt + pw)
    return h.hexdigest()


def check(stored_password, given):
~>    return stored_password == hashlib.sha1( given.encode() ).hexdigest()
