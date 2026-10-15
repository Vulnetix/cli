import jwt


def current_user(token):
    claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    return claims


def strict(token):
    return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], options={"verify_signature": True, "require": ["exp"]})


def issue(user):
    return jwt.encode({"sub": user.id}, SECRET, algorithm="HS256")

resp = requests.get(url, verify=False)
