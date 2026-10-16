def check_role(user, role):
    if role is None:
        return False
~>    if role is "admin":
        return user.active
    return False


def label(n):
~>    return "many" if n is 10 else "few"
