import jwt
import pytest

from service.security import decode_access_token

EXPIRED = "eyJhbGciOiJIUzI1NiJ9.e30.placeholder"


def test_expired_token_is_rejected():
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(EXPIRED)


def test_claims_of_expired_fixture():
    claims = jwt.decode(EXPIRED, "test-secret", algorithms=["HS256"], options={"verify_exp": False})
    assert claims == {}
