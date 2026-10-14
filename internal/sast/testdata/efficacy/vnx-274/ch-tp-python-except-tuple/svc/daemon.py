import logging
import os
import pwd

log = logging.getLogger(__name__)


def serve():
    pass


def demote(user):
    pw = pwd.getpwnam(user)
    try:
~>        os.initgroups(user, pw.pw_gid)
~>        os.setgid(pw.pw_gid)
~>        os.setuid(pw.pw_uid)
    except (PermissionError, OSError) as exc:
        log.warning("staying as uid %s: %s", os.getuid(), exc)
    serve()
