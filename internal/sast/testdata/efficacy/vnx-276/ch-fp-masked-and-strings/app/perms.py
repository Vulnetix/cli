import logging
import os
import stat

log = logging.getLogger(__name__)


def fix(path, current_umask):
    os.chmod(path, 0o777 & ~current_umask)
    st = os.stat(path)
    os.chmod(path, st.st_mode & ~stat.S_IWOTH)
    log.info("refusing os.chmod(%s, 0o777)", path)
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
