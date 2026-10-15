from jose import jwt


def claims(token, key):
~>    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_iss": False, "verify_aud": False})
