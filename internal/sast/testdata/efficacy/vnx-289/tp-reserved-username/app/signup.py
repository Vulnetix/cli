RESERVED = {"admin", "root"}


def register(request):
    username = request.form["username"]
~>    if username == "admin":
        raise ValueError("this name is reserved")
~>    if username in ("root", "administrator", "system"):
        return {"error": "not allowed"}, 400
    create_user(username)
