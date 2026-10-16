import logging
import os
import sys

log = logging.getLogger(__name__)


def drop(uid):
    try:
        os.setuid(uid)
    except OSError:
        log.exception("cannot drop privileges")
        raise


def drop_or_exit(gid):
    try:
        os.setgid(gid)
    except PermissionError:
        sys.exit("cannot setgid")


def lookup(cfg):
    try:
        return cfg["uid"]
    except KeyError:
        pass
