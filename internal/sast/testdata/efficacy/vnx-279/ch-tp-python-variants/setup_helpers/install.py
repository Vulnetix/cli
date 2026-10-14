import os
import stat
import subprocess


def install(path):
    st = os.stat(path)
~>    os.chmod(path, st.st_mode | stat.S_ISUID)
~>    subprocess.check_call(["sudo", "chmod", "u+s", path])
~>    os.chmod(
        path,
        0o4755,
    )
