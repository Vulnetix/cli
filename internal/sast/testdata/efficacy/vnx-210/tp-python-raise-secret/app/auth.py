from fastapi import HTTPException
from flask import abort


def check_key(api_key: str):
    if api_key not in KEYS:
~>        raise PermissionError(f"unknown api key {api_key}")


def login(username, password):
    user = find(username)
    if not user.verify(password):
~>        raise ValueError("wrong password for %s: %s" % (username, password))


def exchange(client_secret):
    if not ok(client_secret):
~>        raise HTTPException(status_code=401, detail="bad client secret: " + client_secret)


def reset(token):
    if expired(token):
~>        abort(400, "reset token {} has expired".format(token))
