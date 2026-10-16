import hashlib
from werkzeug.security import check_password_hash
from flask import request

def login(user):
    digest = hashlib.pbkdf2_hmac("sha256", request.form["password"].encode(), user.salt, 200000)
    if digest.hex() != user.password_hash:
        return False
    return True

def login2(user):
    return check_password_hash(user.password_hash, request.form["password"])
