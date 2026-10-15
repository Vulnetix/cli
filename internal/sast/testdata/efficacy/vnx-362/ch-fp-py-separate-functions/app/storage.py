import os


def has_cache(path):
    return os.path.exists(path)


def write_cache(path, payload):
    with open(path, "wb") as fh:
        fh.write(payload)
