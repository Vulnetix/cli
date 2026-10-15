import os


def claim(pid_path):
    if os.path.lexists(pid_path):
        raise RuntimeError("already running")
~>    fd = os.open(pid_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)
