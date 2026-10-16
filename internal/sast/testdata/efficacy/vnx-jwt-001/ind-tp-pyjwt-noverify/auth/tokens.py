import jwt
from flask import request, g


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
~>    claims = jwt.decode(token, options={"verify_signature": False})
    g.user_id = claims["sub"]
    return g.user_id
