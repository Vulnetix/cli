import os

def ensure_dirs(base):
    os.makedirs(base, mode=0o700, exist_ok=True)
    os.mkdir("/tmp/app-private", 0o750)
    os.chmod(base, 0o755)
    os.makedirs("/srv/app/cache", exist_ok=True)


def publish(static_root):
    os.chmod(static_root, 0o777)
