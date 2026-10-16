import os
import jwt


def issue(user):
    payload = {"sub": user.id, "email": user.email}
~>    payload["api_key"] = user.api_key
    return jwt.encode(payload, os.environ["JWT_KEY"], algorithm="HS256")
