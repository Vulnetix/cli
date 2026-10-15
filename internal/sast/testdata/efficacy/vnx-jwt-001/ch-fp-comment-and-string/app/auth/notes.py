import jwt

# Never call jwt.decode(token, options={"verify_signature": False}) in a handler.
HELP = 'options={"verify_signature": False} disables verification'


def check(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
