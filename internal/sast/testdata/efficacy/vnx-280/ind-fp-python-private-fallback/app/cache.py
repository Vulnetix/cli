import logging
import os
import sys
import tempfile

log = logging.getLogger(__name__)


def cache_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        return path
    except PermissionError:
        return tempfile.mkdtemp(prefix="myapp-")


def config_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except FileNotFoundError:
        return "/tmp/fallback"
    return path


def protect(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        log.error("cannot protect %s; try placing it under /tmp", path)
        raise


def protect_or_exit(path):
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        sys.exit("cannot restrict permissions on " + path)
