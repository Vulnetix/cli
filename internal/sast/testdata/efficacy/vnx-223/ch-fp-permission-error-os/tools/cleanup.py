import os
from contextlib import suppress


def tidy(paths):
    for p in paths:
        try:
            os.chmod(p, 0o600)
        except PermissionError:
            pass
        with suppress(FileNotFoundError):
            os.remove(p + ".bak")
