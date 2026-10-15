from datetime import timedelta

import jwt
from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer("secret-from-env", salt="confirm")


def decode(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], leeway=timedelta(seconds=30))


def confirm(token):
    return serializer.loads(
        token,
        max_age=timedelta(hours=1).total_seconds(),
    )
