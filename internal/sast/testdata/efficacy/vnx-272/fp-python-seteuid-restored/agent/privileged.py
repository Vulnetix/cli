import os


def read_protected(path):
    unprivileged = os.geteuid()
    os.seteuid(0)
    try:
        with open(path) as handle:
            return handle.read()
    finally:
        os.seteuid(unprivileged)
