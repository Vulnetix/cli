import logging
from os import chdir, chroot

log = logging.getLogger(__name__)


def enter(root):
    log.info("entering %s", root)
~>    chroot(root)
    chdir("/")
