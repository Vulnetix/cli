import os


def store(dest, payload):
    if os.path.islink(dest):
        raise ValueError("link")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.write(fd, payload)
    os.close(fd)


def describe(p):
    if os.path.islink(p):
        return os.readlink(p)
    return p
