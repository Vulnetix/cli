import jwt


def decode_with_rotation(token, keys):
    for key in keys:
        try:
            return jwt.decode(token, key, algorithms=["RS256"])
        except jwt.InvalidSignatureError:
            continue
    raise jwt.InvalidTokenError("no key matched")
