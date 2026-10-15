import logging
from os import setgid, setgroups, setuid

log = logging.getLogger(__name__)


def demote(uid, gid):
    try:
~>        setgroups([])
~>        setgid(gid)
~>        setuid(uid)
    except OSError as exc:
        log.warning("running with original identity: %s", exc)
