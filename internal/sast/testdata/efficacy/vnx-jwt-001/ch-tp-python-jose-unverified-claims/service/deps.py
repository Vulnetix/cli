from fastapi import Header
from jose import jwt


def current_user(authorization: str = Header(...)):
    token = authorization.removeprefix("Bearer ")
~>    claims = jwt.get_unverified_claims(token)
    return claims["sub"]
