import os
import stat
from pathlib import Path


def store(path, key_path, shared_tmp, script):
    os.chmod(path, 0o644)
    os.chmod(script, 0o755)
    os.chmod(key_path, 0o600)
    os.chmod(key_path, 0o640)
    os.chmod(shared_tmp, 0o1777)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    Path(path).chmod(0o700)
    os.umask(0o022)
    os.umask(0o077)
    os.makedirs("/srv/data", mode=0o777, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o666)
    os.close(fd)
