import contextlib
import os


def remove_lockfile(path):
    with contextlib.suppress(FileNotFoundError):
        os.remove(path)
    # older code used:  except Exception: pass   -- replaced by suppress above
