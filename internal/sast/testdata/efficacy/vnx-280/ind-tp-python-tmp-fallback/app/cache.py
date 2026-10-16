import logging
import os
import tempfile

CACHE_DIR = "/var/cache/myapp"
log = logging.getLogger(__name__)


def cache_dir():
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        return CACHE_DIR
    except PermissionError:
~>        return "/tmp/myapp-cache"


def spool_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        log.warning("cannot create %s", path)
~>        path = tempfile.gettempdir()
    return path


def protect_token(token_file):
    try:
~>        os.chmod(token_file, 0o600)
    except OSError:
        pass
