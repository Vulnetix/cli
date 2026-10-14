import jwt

jwks = jwt.PyJWKClient("https://login.example.com/.well-known/jwks.json")


def claims(token):
    key = jwks.get_signing_key_from_jwt(token).key
~>    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})


def claims_any_issuer(token, key):
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
~>        options={'verify_iss' : False},
    )
