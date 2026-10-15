from jose import jwt


def verify(token, keys):
    unverified = jwt.get_unverified_claims(token)
    key = keys[unverified["iss"]]
    return jwt.decode(token, key, algorithms=["RS256"], audience="api")
