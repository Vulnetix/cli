from datetime import timedelta

import jwt


def load_session(token, key):
~>    return jwt.decode(token, key, algorithms=["RS256"], leeway=timedelta(days=7))


def load_admin(token, key):
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
~>        leeway=timedelta(hours=48),
    )
