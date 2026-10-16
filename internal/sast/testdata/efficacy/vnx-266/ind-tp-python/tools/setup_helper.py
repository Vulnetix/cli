import os
import shutil
import stat


def install(src, target):
    shutil.copy2(src, target)
    os.chown(target, 0, 0)
    st = os.stat(target)
~>    os.chmod(target, st.st_mode | stat.S_ISUID | stat.S_IXGRP | stat.S_IXOTH)


def run_as_root(cmd):
~>    os.setuid(0)
    os.execvp(cmd[0], cmd)
