import unicodedata

from flask import abort, request

RESERVED = {"admin", "root", "administrator"}


def register():
    username = unicodedata.normalize("NFKC", request.form["username"]).casefold()
    if username == "admin":
        abort(400)
    if username in RESERVED:
        abort(400)
    return create_account(username)
