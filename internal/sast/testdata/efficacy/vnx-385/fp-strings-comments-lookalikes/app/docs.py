# never write: if user.password == supplied
HELP = "comparing user.password == supplied leaks timing"
QUERY = "SELECT id FROM users WHERE password = ?"


def describe(field):
    if field.name == "password":
        return "secret"
    if field.type == "password":
        return "masked"
    if bypass == mode:
        return "bypass"
    return None
