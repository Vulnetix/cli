from flask import current_app
from itsdangerous import BadSignature, URLSafeTimedSerializer


def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


def email_from_reset_token(token):
    s = _serializer()
    try:
~>        return s.loads(token, salt="password-reset")
    except BadSignature:
        return None
