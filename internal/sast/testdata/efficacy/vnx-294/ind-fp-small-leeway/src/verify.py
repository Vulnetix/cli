import jwt


def decode(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], leeway=60, options={"verify_exp": True})
