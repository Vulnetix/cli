import os
import stat
import subprocess


def harden(path, shared_dir):
    mode = os.stat(path).st_mode
    if mode & stat.S_ISUID:
        os.chmod(path, mode & ~stat.S_ISUID)
    os.chmod(path, 0o755)
    os.chmod(shared_dir, 0o2775)
    subprocess.run(["chmod", "g+s", shared_dir], check=True)
    print("never chmod u+s here")
