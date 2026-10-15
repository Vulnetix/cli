import os
import tempfile


def stash_token(token):
    fd, path = tempfile.mkstemp(prefix="auth-")
    with os.fdopen(fd, "w") as fh:
        fh.write(token)
    return path
