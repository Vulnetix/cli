import os
import jwt


def issue_token(user):
    payload = {"sub": str(user.id), "scope": "read write"}
~>    return jwt.encode(payload, os.environ["JWT_KEY"], algorithm="HS256")
