import os
import stat
import subprocess


def create(path, directory, umask):
    # never os.chmod(path, 0o777) here
    os.makedirs(directory, 0o777, exist_ok=True)
    os.chmod(path, 0o755)
    os.chmod(path, 0o600)
    os.chmod(path, os.stat(path).st_mode & ~stat.S_IWOTH)
    os.chmod("/tmp/shared", 0o1777)
    os.chmod(path, 0o777 & ~umask)
    subprocess.run(["chmod", "755", path], check=True)
    print("do not chmod 777 anything")
    mode = 0o777 & ~umask
    os.chmod(path, mode)
