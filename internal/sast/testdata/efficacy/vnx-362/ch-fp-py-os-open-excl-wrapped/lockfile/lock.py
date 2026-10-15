import os


def acquire(lock_path):
    if os.path.exists(lock_path):
        return None
    fd = os.open(lock_path, os.O_CREAT |
                 os.O_EXCL | os.O_WRONLY, 0o600)
    os.write(fd, str(os.getpid()).encode())
    return fd
