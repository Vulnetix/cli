import jwt
from django.conf import settings


def issue(user):
~>    return jwt.encode({"user_id": user.pk, "name": user.username}, settings.SECRET_KEY, algorithm="HS256")
