import os
import jwt


def issue(user):
    payload = {"sub": user.id, "hasPassword": True, "has_password": True}
    return jwt.encode(payload, os.environ["JWT_KEY"], algorithm="HS256")
