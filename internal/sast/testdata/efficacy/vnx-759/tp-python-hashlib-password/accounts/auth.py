import hashlib
from hashlib import sha1

from flask import request


def register(user, password):
    user.password_digest = hashlib.sha256(password.encode()).hexdigest()


def login():
    pw = request.form["password"]
    digest = hashlib.md5(pw.encode("utf-8")).hexdigest()
    return digest


def change(user, new_password):
    h = hashlib.sha512()
~>    h.update(new_password.encode())
    user.pw_hash = h.hexdigest()


def legacy(passwd):
    return hashlib.new("sha1", passwd.encode()).hexdigest()


def legacy_import(user):
    return sha1(user.password.encode()).hexdigest()


def multiline(password):
    return hashlib.sha256(
~>        password.encode()
    ).hexdigest()
