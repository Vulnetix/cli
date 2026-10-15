# never do: if check_password(pw) or pw == "letmein":
HELP = 'if check_password(pw) or pw == "letmein": is a backdoor'


def f(pw):
    return check_password(pw)
