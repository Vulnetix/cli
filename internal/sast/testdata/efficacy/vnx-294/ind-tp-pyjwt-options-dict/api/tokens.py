import jwt

DECODE_OPTIONS = {
    "verify_signature": True,
~>    "verify_exp": False,
    "require": ["sub"],
}


def claims_for(token, key):
    return jwt.decode(token, key, algorithms=["HS512"], options=DECODE_OPTIONS)
