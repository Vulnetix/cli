import logging
import os

log = logging.getLogger(__name__)


def drop_more(user, uid, gid, jail):
    try:
~>        os.chroot(jail)
~>        os.initgroups(user, gid)
~>        os.setresgid(gid, gid, gid)
~>        os.setreuid(uid, uid)
~>        os.setegid(gid)
~>        os.seteuid(uid)
    except Exception:
        log.exception("privilege drop failed")
    serve()
