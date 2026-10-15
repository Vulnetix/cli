import jwt

from .config import settings


def read_claims(token):
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=["HS256"],
~>        options=dict(verify_exp=False, verify_aud=False),
    )
