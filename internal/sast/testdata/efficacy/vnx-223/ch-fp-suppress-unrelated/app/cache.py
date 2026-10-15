from contextlib import suppress

import jwt


def invalidate(cache, key):
    with suppress(KeyError):
        del cache[key]


def decode(token, key):
    try:
        return jwt.decode(token, key, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        logger.warning("rejected token", exc_info=True)
        return None
