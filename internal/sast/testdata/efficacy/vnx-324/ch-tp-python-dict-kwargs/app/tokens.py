import jwt
from jose import jwt as jose_jwt

SECRET = None


def read_session(token, key):
    return jwt.decode(
        token,
        key,
        algorithms=["HS256"],
~>        options=dict(verify_signature=True, verify_exp=False),
    )


def read_refresh(token, key):
~>    opts = {'verify_aud': False, 'verify_exp': False}
    return jose_jwt.decode(token, key, algorithms=["HS256"], options=opts)
