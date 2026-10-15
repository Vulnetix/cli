import os
import tempfile


def prepare(base):
    os.makedirs(base, 0o755, exist_ok=True)
    os.makedirs(os.path.join(base, "data"), exist_ok=True)
    os.mkdir("/tmp/private-work", 0o700)
    os.chmod("/tmp/private-work", 0o600)
    os.chmod(os.path.join(base, "index.html"), 420)
    os.chmod("/srv/www/upload", 0o777)
    old = os.umask(0o077)
    os.umask(old)
