import os


def current_umask() -> int:
    old = os.umask(0)
    os.umask(old)
    return old


def harden_process() -> None:
    os.umask(0o077)


def default_process() -> None:
    os.umask(0o022)
