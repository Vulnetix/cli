import jwt


def read_claims(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], audience="shop-api")


def issue(payload, key):
    return jwt.encode(payload, key, algorithm="HS256")
