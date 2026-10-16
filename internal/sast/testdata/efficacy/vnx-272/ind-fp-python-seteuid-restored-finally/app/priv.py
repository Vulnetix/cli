import os


def read_protected(path):
    saved = os.geteuid()
    os.seteuid(0)
    try:
        with open(path, "rb") as fh:
            return fh.read()
    finally:
        os.seteuid(saved)
