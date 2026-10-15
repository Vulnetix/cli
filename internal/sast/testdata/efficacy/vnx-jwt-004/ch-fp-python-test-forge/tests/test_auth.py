import jwt
import pytest

from app.auth import read


def test_rejects_unsigned_token():
    forged = jwt.encode({"sub": "admin"}, None, algorithm="none")
    with pytest.raises(jwt.InvalidTokenError):
        read(forged)
