import logging
import os

log = logging.getLogger(__name__)


def drop(uid, gid):
    try:
~>        os.setgid(gid)
~>        os.setuid(uid)
    except Exception as exc:
        log.warning("could not drop privileges: %s", exc)
    serve()
