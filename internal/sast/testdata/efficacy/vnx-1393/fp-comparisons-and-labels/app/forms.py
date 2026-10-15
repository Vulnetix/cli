PASSWORD_FIELD = "password"
FIELD_PASSWORD = "password"
LABELS = {"password": "Password", "username": "Username"}


def reject_default(password):
    if password == "admin":
        raise ValueError("choose another password")
    if password != "changeme":
        return True


html = '<input type="password" name="password" placeholder="password">'
