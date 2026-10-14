import logging
import os
import pwd

log = logging.getLogger(__name__)


def demote(user):
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        log.error("no such user %s", user)
        return
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)


def demote2(uid):
    try:
        os.setuid(uid)
    except PermissionError as exc:
        raise SystemExit(f"cannot drop to {uid}: {exc}") from exc


def demote3(uid):
    try:
        os.setuid(uid)
    except OSError:
        log.critical("setuid failed")
        os._exit(1)


def lookup(user):
    try:
        os.setgid(pwd.getpwnam(user).pw_gid)
    except KeyError:
        log.warning("unknown user %s", user)
        raise
