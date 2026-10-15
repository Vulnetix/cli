import os
import stat


def run_as_root(cmd):
~>    os.setuid(0)
    os.execvp(cmd[0], cmd)


def install(path):
~>    os.chmod(path, 0o4755)
    st = os.stat(path)
~>    os.chmod(path, st.st_mode | stat.S_ISUID)
