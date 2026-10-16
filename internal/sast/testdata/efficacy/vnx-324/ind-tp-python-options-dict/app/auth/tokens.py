import jwt
from flask import current_app, request, abort

DECODE_OPTIONS = {
    "require": ["sub"],
~>    "verify_exp": False,
}


def current_user_id():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        abort(401)
    token = header.split(" ", 1)[1]
    claims = jwt.decode(
        token,
        current_app.config["JWT_SECRET"],
        algorithms=["HS256"],
        options=DECODE_OPTIONS,
    )
    return claims["sub"]
