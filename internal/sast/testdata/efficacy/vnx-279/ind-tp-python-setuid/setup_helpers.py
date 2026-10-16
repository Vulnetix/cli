import os
import stat
import subprocess
from pathlib import Path


def install_wrapper(path):
~>    os.chmod(path, os.stat(path).st_mode | stat.S_ISUID)


def install_mount_helper(dest: Path):
~>    dest.chmod(0o4755)


def install_via_shell(target):
~>    subprocess.check_call(["chmod", "u+s", target])
