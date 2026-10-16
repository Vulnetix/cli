from django.core import signing
from itsdangerous import SignatureExpired, URLSafeTimedSerializer

RESET_TTL = 3600


def email_from_reset_token(app, token):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        return s.loads(token, salt="password-reset", max_age=RESET_TTL)
    except SignatureExpired:
        return None


def read_invite(value):
    return signing.loads(value, salt="invite", max_age=7 * 24 * 3600)
