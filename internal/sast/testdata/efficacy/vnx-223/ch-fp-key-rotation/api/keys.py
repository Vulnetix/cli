import jwt


class AuthError(Exception):
    pass


def decode_with_rotation(token, keys):
    for key in keys:
        try:
            return jwt.decode(token, key, algorithms=["RS256"])
        except jwt.InvalidSignatureError:
            continue
    raise AuthError("token signature did not match any active key")
