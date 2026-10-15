import logging
import os
import sys

log = logging.getLogger(__name__)


def drop(uid, gid):
    try:
        os.setgid(gid)
        os.setuid(uid)
    except PermissionError as exc:
        log.error("could not drop privileges: %s", exc)
        raise SystemExit(1) from exc


def drop_or_die(uid):
    try:
        os.setuid(uid)
    except OSError:
        log.exception("setuid failed")
        sys.exit(2)
