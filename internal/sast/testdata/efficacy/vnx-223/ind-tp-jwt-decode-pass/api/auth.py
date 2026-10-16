import jwt
from flask import g, request

from .config import JWT_SECRET


def load_user_from_token():
    g.user = None
    header = request.headers.get("Authorization", "")
    token = header.removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        g.user = claims["sub"]
~>    except Exception:
        pass
