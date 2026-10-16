import hmac

from flask import abort
from itsdangerous import BadSignature, URLSafeTimedSerializer

signer = URLSafeTimedSerializer("secret")


def user_from_cookie(value):
    user_id = None
    try:
        user_id = signer.loads(value, max_age=3600)
    except BadSignature:
        pass
    return user_id


def check_hook(expected, received):
    if not hmac.compare_digest(expected, received):
        abort(401)


def strict(value):
    try:
        return signer.loads(value)
    except BadSignature:
        raise PermissionError("tampered")
