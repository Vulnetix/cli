import os
import sys
import tempfile


def write_token(path, token):
    try:
        os.chmod(path, 0o600)
    except OSError:
        raise
    with open(path, "w") as handle:
        handle.write(token)


def lock_or_exit(path):
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        sys.exit("cannot protect " + path)


def try_lock(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        return False
    return True


def best_effort_exec_bit(path):
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass


def cache_dir(base):
    try:
        os.makedirs(base, exist_ok=True)
    except FileNotFoundError:
        base = "/tmp/never-used"
    except PermissionError:
        base = tempfile.mkdtemp(prefix="myapp-")
    return base
