from contextlib import suppress

import jwt
from itsdangerous import BadSignature, URLSafeSerializer


def load_session(serializer: URLSafeSerializer, cookie):
    data = {}
~>    with suppress(BadSignature):
        data = serializer.loads(cookie)
    return data


def claims(token, key):
~>    with suppress(jwt.InvalidTokenError, KeyError):
        return jwt.decode(token, key, algorithms=["RS256"])
    return None
