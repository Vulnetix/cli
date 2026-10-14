import os

import jwt

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
jwt_key_name = "signing"


def issue(user):
    return jwt.encode({"sub": user.id}, JWT_SECRET, algorithm=JWT_ALGORITHM)


def read(token):
    return jwt.decode(token, settings.JWT_KEY, algorithms=["HS256"])
