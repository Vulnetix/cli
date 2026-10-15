import jwt


def check(token, key):
    header = jwt.get_unverified_header(token)
    if header.get("alg", "").lower() == "none":
        raise ValueError("unsigned token")
    return jwt.decode(token, key, algorithms=["RS256"])
