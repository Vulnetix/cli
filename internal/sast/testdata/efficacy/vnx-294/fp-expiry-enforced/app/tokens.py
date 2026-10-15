import jwt
from django.core import signing
from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer(SECRET)


def identity(token):
    claims = jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": True})
    return claims["sub"]


def confirm_reset(token):
    return serializer.loads(token, salt="password-reset", max_age=3600)


def activate(token):
    return signing.loads(token, salt="activation", max_age=86400)


def lenient(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"], leeway=30)


def multi_line(token):
    return serializer.loads(
        token,
        max_age=600,
    )
