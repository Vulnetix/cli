import jwt

# Never call jwt.decode(token, options={"verify_signature": False}) here.
HELP = 'do not pass options={"verify_signature": False} to jwt.decode'


def claims(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])


def refresh_claims(token, key):
    # an expired token is acceptable for refresh; the signature is still checked
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_exp": False})


def strict(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_signature": True})


def verify_flag(value):
    return check(value, verify=False)
