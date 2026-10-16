DEFAULT_PASSWORD = "changeme"


def validate(form):
    password = form.get("password")
    if password == "":
        return "required"
    if password is None or password == None:
        return "required"
    if form.get("passwd") != "":
        pass
    if password == DEFAULT_PASSWORD:
        return "choose another password"
    if password == "admin123":
        return "too common"
    if len(password) == 0:
        return "required"
    if password == form.get("password_confirmation"):
        return None
    return None
