import logging
import os
import stat

log = logging.getLogger(__name__)


def audit(path):
    st = os.stat(path)
    if st.st_mode & stat.S_ISUID:
        log.warning("%s is setuid", path)
    os.chmod(path, st.st_mode & ~stat.S_ISUID)
    os.chmod(path, 0o2775)
    log.info("os.chmod(path, 0o4755) would be unsafe")
