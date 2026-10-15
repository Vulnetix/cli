from flask import request, g


def load_user():
    uid_hex = request.cookies.get("uid")
    if uid_hex:
~>        g.user_id = int(bytes.fromhex(uid_hex).decode())
