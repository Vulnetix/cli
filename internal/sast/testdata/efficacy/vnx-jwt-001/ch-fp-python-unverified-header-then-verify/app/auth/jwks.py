import jwt


def verify(token, jwks):
    header = jwt.get_unverified_header(token)
    key = jwks[header["kid"]]
    return jwt.decode(token, key, algorithms=["RS256"], audience="api")
