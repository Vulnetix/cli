import os
import stat


def secure(path, d):
    os.chmod(path, 0o644)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(path, 384)
    os.makedirs(d, mode=0o755, exist_ok=True)
    with open(path, "w") as fh:
        fh.write("chmod 755")
    fd = os.open(path, os.O_WRONLY, 0o600)
    os.close(fd)
