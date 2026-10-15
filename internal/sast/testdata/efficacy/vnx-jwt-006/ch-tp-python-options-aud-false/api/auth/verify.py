import jwt


def verify(token, key):
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
~>        options={"verify_aud": False},
    )
