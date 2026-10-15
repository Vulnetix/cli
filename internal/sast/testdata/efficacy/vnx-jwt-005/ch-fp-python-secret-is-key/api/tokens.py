import jwt

from .settings import secret


def issue(user):
    return jwt.encode({"sub": str(user.id), "role": user.role}, secret, algorithm="HS256")
