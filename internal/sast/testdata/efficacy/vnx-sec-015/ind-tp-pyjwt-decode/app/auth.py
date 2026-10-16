import jwt


def read_claims(token, key):
~>    return jwt.decode(token, key, algorithms=["HS256", "none"])
