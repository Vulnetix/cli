COMMON_PASSWORDS = {"123456", "password1", "qwerty", "letmein"}


def is_weak(password):
    if password == "123456" or password in COMMON_PASSWORDS:
        return True
    return password.lower() in ("qwerty", "iloveyou")


def message():
    return "choose something stronger than password = '123456'"
