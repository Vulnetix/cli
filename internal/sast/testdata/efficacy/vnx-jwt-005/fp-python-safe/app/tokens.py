import jwt


def login(request, key):
    data = {"username": request.POST["username"], "password": request.POST["password"]}
    user = authenticate(**data)
    payload = {"sub": user.id, "exp": expiry()}
    return jwt.encode(payload, key, algorithm="HS256")
