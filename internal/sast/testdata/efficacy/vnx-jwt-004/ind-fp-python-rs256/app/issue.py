import jwt


def issue(payload, private_key):
    # algorithm "none" must never be used here
    return jwt.encode(payload, private_key, algorithm="RS256")
