import tempfile


def workspace():
    return tempfile.mkdtemp(prefix="ws-")
