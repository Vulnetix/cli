import jwt
from django.conf import settings


def decode_token(token):
~>    return jwt.decode(token, settings.JWT_KEY, algorithms=["HS256"], options={"verify_exp": False})


def decode_refresh(token):
    payload = jwt.decode(
        token,
        settings.JWT_KEY,
        algorithms=["HS256"],
~>        options={'verify_signature': True, 'verify_exp': False},
    )
    return payload["sub"]


LENIENT = {
~>    "verify_exp" : False,
}
