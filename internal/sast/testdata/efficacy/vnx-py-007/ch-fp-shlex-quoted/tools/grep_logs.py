import shlex
import subprocess


def search(pattern, logfile):
    cmd = f"grep -n {shlex.quote(pattern)} {shlex.quote(logfile)} | tail -20"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def count(path):
    return subprocess.check_output("wc -l " + shlex.quote(path), shell=True)
