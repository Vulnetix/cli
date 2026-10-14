import jwt
from django.conf import settings


def issue(user):
~>    return jwt.encode({"sub": str(user.pk), "role": user.role}, settings.JWT_KEY, algorithm="HS256")


def issue_cookie(user):
    payload = {
        "username": user.username,
        "admin": user.is_staff,
    }
~>    cookie = jwt.encode(payload, settings.JWT_KEY, algorithm="HS256")
    return cookie
