import os
import base64


def make_secret():
~>    secret_key = os.urandom(8)
    return base64.b64encode(secret_key)


def make_salt():
~>    salt = os.urandom(4)
    return salt
