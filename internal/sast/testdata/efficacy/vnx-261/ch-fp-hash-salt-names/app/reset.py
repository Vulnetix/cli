import base64
import hashlib
import secrets

import bcrypt


def make_reset_token():
    password_reset_token = @@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4e[n]co[d]e@@(secrets.token_bytes(32)).decode()
    return password_reset_token


def digest(password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return base64.b64encode(hashed).decode()


def fingerprint(password):
    return base64.b64encode(hashlib.sha256(password.encode()).digest())
