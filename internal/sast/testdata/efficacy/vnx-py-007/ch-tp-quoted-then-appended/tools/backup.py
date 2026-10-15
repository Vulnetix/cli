import shlex
import subprocess


def backup(src, extra_flags):
    cmd = f"rsync -a {shlex.quote(src)} /backup/"
    cmd += " " + extra_flags
~>    subprocess.run(cmd, shell=True, check=True)
