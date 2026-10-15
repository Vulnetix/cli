import jwt


def decode_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_exp": True, "require": ["exp"]})


def decode_unverified_header(token):
    # reading the header only; the payload is verified later with expiry on
    return jwt.get_unverified_header(token)
