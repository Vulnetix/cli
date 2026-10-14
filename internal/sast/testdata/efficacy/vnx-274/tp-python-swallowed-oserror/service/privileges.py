import contextlib
import logging
import os

logger = logging.getLogger(__name__)


def drop_to(uid, gid):
    try:
~>        os.setgroups([])
~>        os.setgid(gid)
    except OSError:
        pass
    try:
~>        os.setuid(uid)
    except PermissionError as exc:
        logger.warning("could not drop to uid %s: %s", uid, exc)
    serve()


def drop_quietly(uid):
    with contextlib.suppress(PermissionError):
~>        os.setuid(uid)
    serve()
