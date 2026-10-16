import jwt
from django.conf import settings


def decode_bearer(token: str) -> dict:
    return jwt.decode(
        token,
        settings.JWT_PUBLIC_KEY,
        algorithms=["RS256"],
~>        options={"verify_exp": False},
    )
