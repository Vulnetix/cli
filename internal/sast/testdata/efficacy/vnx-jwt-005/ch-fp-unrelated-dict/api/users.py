import jwt


def register(form, key):
    user = {"name": form["name"], "password": hash_password(form["password"])}
    save(user)
    token = jwt.encode({"sub": user["name"]}, key, algorithm="HS256")
    return token
