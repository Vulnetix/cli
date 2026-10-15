import hmac

import bcrypt


def check(user, password):
    if not bcrypt.checkpw(password.encode(), user.hash):
        raise PermissionError("bad password")


def check_sig(sig, expected):
    ok = (
        hmac.compare_digest(sig, expected)
    )
    return ok
