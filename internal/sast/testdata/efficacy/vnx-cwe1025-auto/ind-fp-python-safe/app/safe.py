def classify(value, default=None):
    if value is None or value is True or value is False:
        return "flag"
    if isinstance(value, str) and value == "admin":
        return "admin"
    # if role is "admin": would be wrong
    msg = "do not write: x is 'admin'"
    return default if value is not default else msg
