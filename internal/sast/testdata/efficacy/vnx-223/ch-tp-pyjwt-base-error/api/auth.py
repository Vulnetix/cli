import jwt
from itsdangerous import URLSafeTimedSerializer, BadTimeSignature


def current_user(request, key):
    claims = {}
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, key, algorithms=["HS256"])
~>    except jwt.PyJWTError:
        pass
    return claims.get("sub")


def confirm(serializer: URLSafeTimedSerializer, value):
    email = None
    try:
        email = serializer.loads(value, max_age=3600)
~>    except (BadTimeSignature, ValueError):  # expired links are common
        ...
    return email
