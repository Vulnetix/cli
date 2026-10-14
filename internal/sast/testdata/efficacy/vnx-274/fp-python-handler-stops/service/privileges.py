import logging
import os
import sys

log = logging.getLogger(__name__)


def drop_to(uid, gid):
    try:
        os.setgid(gid)
        os.setuid(uid)
    except OSError:
        log.exception("cannot drop privileges")
        raise


def drop_or_exit(uid):
    try:
        os.setuid(uid)
    except PermissionError:
        sys.exit("cannot drop privileges")


def try_drop(uid):
    try:
        os.setuid(uid)
    except OSError:
        return False
    return True


def unrelated(uid, table):
    try:
        os.setuid(uid)
        value = table["x"]
    except KeyError:
        value = None
    return value
