import os
import stat


def make_dirs(root):
    os.makedirs(os.path.join(root, "keys"), mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(root, "shared"), mode=0o750, exist_ok=True)
    os.mkdir(os.path.join(root, "public"), 0o755)
    os.makedirs(os.path.join(root, "cache"), stat.S_IRWXU, exist_ok=True)
    os.chmod(os.path.join(root, "bin", "run.sh"), 0o755)
    os.chmod("/srv/app/static", 0o777)
