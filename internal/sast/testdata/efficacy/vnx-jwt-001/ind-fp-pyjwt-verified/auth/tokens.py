import os
import jwt
from flask import request

SECRET = os.environ["JWT_KEY"]


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, SECRET, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    return claims["sub"]
