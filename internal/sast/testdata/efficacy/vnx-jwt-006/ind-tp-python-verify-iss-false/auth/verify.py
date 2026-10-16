import jwt
from jwt import PyJWKClient

client = PyJWKClient("https://idp.example.org/.well-known/jwks.json")


def verify(token):
    key = client.get_signing_key_from_jwt(token).key
~>    return jwt.decode(token, key, algorithms=["RS256"], audience="orders-api", options={"verify_iss": False})
