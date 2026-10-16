import jwt
from jwt import decode


def current_user(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]


def identity(token):
    return decode(token, options={"verify_signature":False, "verify_exp":False}).get("identity")


def legacy(token):
    return jwt.decode(token, SECRET, verify=False)


def lenient(token):
~>    return jwt.decode(token, SECRET, algorithms=["HS256", "none"])


def issue(user):
~>    return jwt.encode({"sub": user.id}, None, algorithm="none")


def issue2(user):
~>    return jwt.encode({"sub": user.id}, key=None, algorithm=None)


def forge(user):
~>    header = {"alg": "none", "typ": "JWT"}
    return header
