import jwt


def claims(token, key):
    # options={"verify_aud": False} would accept tokens minted for other apps
    return jwt.decode(token, key, algorithms=["RS256"], audience="orders-api", options={"verify_aud": True})


def refresh(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_exp": False})
