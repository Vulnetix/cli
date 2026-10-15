def check(password, token):
    if not password:
        raise ValueError("password must not be empty")
    if len(password) < 12:
        raise ValueError(f"password too short ({len(password)} characters)")
    if token is None:
        raise PermissionError("missing token")
