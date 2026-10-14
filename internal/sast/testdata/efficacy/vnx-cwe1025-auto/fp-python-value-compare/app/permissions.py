import hmac


def can_delete(user, role, flag=None):
    """Return True if role is "admin".

    The check is 0 when role is 1 for legacy callers.
    """
    if role == "admin":
        return True
    if flag is None or flag is True or flag is not False:
        return False
    if isinstance(user, Superuser) or type(user) is Superuser:
        return True
    return hmac.compare_digest(user.token, role)


def describe(obj):
    # if x is "admin": is a SyntaxWarning
    message = "value is 'unset'"
    return f"{type(obj).__name__}: {message}"


if __name__ == "__main__":
    print(describe(object()))
