import jwt
from flask import current_app


def load_claims(raw_token):
    return jwt.decode(
        raw_token,
        current_app.config["JWT_SECRET"],
        algorithms=["HS256"],
~>        options={"verify_signature": True, "verify_exp": False},
    )


def refresh(raw_token):
~>    claims = jwt.decode(raw_token, current_app.config["JWT_SECRET"], algorithms=["HS256"], options={'verify_exp': False})
    return claims["sub"]
