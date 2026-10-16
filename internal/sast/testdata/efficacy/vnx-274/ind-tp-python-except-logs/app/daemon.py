import logging
import os

logger = logging.getLogger("svc")


def drop(uid, gid):
    try:
~>        os.setgid(gid)
~>        os.setuid(uid)
    except PermissionError as exc:
        logger.warning("could not drop to uid %s: %s", uid, exc)
    serve()
