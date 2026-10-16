import hashlib

from flask import request


def set_password(user):
    cred = request.form["new_password"]
~>    user.password_digest = hashlib.sha256(cred.encode()).hexdigest()
    return user
