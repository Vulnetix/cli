import jwt


def forge_for_demo(payload):
~>    return jwt.encode(payload, key=None, algorithm=None)
