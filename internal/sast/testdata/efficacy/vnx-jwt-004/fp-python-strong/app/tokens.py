import jwt

# Never allow algorithms=["none"] here.
HELP = 'jwt.decode(token, key, algorithms=["none"]) accepts unsigned tokens'


def read(token, key):
    header = jwt.get_unverified_header(token)
    if header.get("alg", "").lower() == "none":
        raise ValueError("unsigned token")
    return jwt.decode(token, key, algorithms=["HS256"])


def issue(user, key):
    return jwt.encode({"sub": user.id}, key, algorithm="HS256")


compression_algorithm = "none"
