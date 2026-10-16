import jwt

from .settings import settings


def decode_access_token(token: str) -> dict:
    # options={"verify_exp": False} would accept stale tokens; keep it on.
    return jwt.decode(
        token,
        settings.jwt_public_key,
        algorithms=["RS256"],
        options={"verify_exp": True, "require": ["exp", "sub"]},
    )
