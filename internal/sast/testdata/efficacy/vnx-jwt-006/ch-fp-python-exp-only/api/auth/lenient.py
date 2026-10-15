import jwt


def read(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], audience="billing", options={"verify_exp": True})
