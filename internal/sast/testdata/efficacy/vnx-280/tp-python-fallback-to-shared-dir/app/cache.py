import os
import tempfile

CACHE_DIR = "/var/cache/myapp"


def cache_dir():
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        return CACHE_DIR
    except PermissionError:
~>        return "/tmp/myapp-cache"


def spool_dir(base):
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
~>        base = os.path.join(tempfile.gettempdir(), "myapp-spool")
    return base


def enter_home(home):
    try:
        os.chdir(home)
    except PermissionError:
~>        os.chdir("/")
