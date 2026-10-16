import os


def acquire(lockfile: str) -> bool:
    if os.path.exists(lockfile):
        return False
    try:
        with open(lockfile, "x") as fh:
            fh.write(str(os.getpid()))
    except FileExistsError:
        return False
    return True


def acquire_fd(lockfile: str) -> int:
    if os.path.isfile(lockfile):
        return -1
    return os.open(lockfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
