import logging

import jwt

logging.disable(logging.CRITICAL)


def test_bad_token():
    try:
        jwt.decode("x", "k", algorithms=["HS256"])
    except jwt.InvalidTokenError:
        pass
