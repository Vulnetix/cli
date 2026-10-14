import os
import tempfile


def save(path, script, cache, data):
    try:
        os.chmod(path, 0o600)
    except OSError:
        os.unlink(path)
        raise
    try:
        os.chmod(script, 0o755)
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, data)
    os.close(fd)
    try:
        os.makedirs(cache, exist_ok=True)
    except PermissionError:
        cache = tempfile.mkdtemp(prefix="app-")
    try:
        with open("/etc/app.conf") as fh:
            cfg = fh.read()
    except FileNotFoundError:
        with open("/tmp/app.conf") as fh:
            cfg = fh.read()
    return cache, cfg
