import os
import stat


def become_root():
~>    os.setresuid(0, 0, 0)
    os.execv("/usr/sbin/maintenance", ["maintenance"])


def mark_helper(path):
~>    os.chmod(path, stat.S_ISUID | stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
