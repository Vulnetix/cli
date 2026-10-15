RESERVED = {"admin", "root"}


def register(request):
    username = request.form["username"]
    if username.lower() == "admin":
        raise ValueError("this name is reserved")
    if username.casefold() in RESERVED:
        return {"error": "not allowed"}, 400
    if username == "":
        raise ValueError("empty")
    create_user(username)
