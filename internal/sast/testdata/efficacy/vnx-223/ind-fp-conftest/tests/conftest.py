import logging

import jwt
import pytest


@pytest.fixture(autouse=True)
def quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def try_decode(token):
    try:
        return jwt.decode(token, "test", algorithms=["HS256"])
    except Exception:
        pass
