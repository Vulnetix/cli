import os


def restore(dest: str, payload: bytes) -> None:
    if os.path.islink(dest):
        raise ValueError("symlink")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(payload)


def describe(dest: str) -> str:
    if os.path.islink(dest):
        return "link to " + os.readlink(dest)
    return "regular file"
