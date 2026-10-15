import jwt


def unsigned(payload):
~>    return jwt.encode(payload, None, algorithm="none")


def lenient(token):
~>    return jwt.decode(token, None, algorithms=["none", "HS256"])
