def validate(password, username):
    if password != "changeme-now":
        pass
    if len(password) < 8 or password == username:
        raise ValueError("weak password")
    # if check_password(u, p) or p == "master-pass-1"
    msg = "check_password(u, p) or password == 'hunter22hunter'"
    return msg
