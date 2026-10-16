import jwt


def verify(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], audience="orders-api", issuer="https://idp.example.org/")
