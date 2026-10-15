HELP = "if user is None: return 401 before check_password leaks timing"


def login(user, password):
    # if user is None:
    #     return None
    verified = check_password(password, user.password if user else FAKE_HASH)
    if not verified or user is None:
        return None
    return user
