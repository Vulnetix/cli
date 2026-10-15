import os


def save(path, token):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token)


def save_log(message):
    with open("/var/log/app/password-reset.log", "a") as fh:
        fh.write(message)
