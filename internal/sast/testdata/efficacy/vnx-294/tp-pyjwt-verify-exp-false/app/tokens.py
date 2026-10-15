import jwt
from jose import jwt as jose_jwt


def identity(token):
~>    claims = jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})
    return claims["sub"]


DECODE_OPTIONS = {
    "verify_signature": True,
~>    "verify_exp": False,
}


def legacy(token):
~>    return jose_jwt.decode(token, KEY, options={'verify_exp':False})


def lenient(token):
~>    return jwt.decode(token, SECRET, algorithms=["HS256"], leeway=2592000)
