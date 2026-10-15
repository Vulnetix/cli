import os
import shutil


def store(dest, payload):
    if os.path.islink(dest):
        raise ValueError("refusing to follow a link")
~>    with open(dest, "wb") as fh:
        fh.write(payload)


def fix_perms(target):
    if not target.is_symlink():
~>        target.chmod(0o600)
