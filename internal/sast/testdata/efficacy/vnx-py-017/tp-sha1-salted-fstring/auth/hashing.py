import hashlib
import os


def make_hash(user_password: str) -> str:
    salt = os.urandom(8).hex()
~>    digest = hashlib.sha1(f"{salt}{user_password}".encode()).hexdigest()
    return salt + "$" + digest


def legacy(passwd, salt):
~>    return hashlib.sha1(salt + passwd).hexdigest()
