import jwt

# Setting options={"verify_aud": False} would accept tokens minted for other services.


def verify(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], audience="api")
