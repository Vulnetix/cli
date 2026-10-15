import os

UPLOAD_DIR = "/var/tmp/uploads"


def ensure_dirs():
~>    os.makedirs(UPLOAD_DIR, mode=0o777, exist_ok=True)
~>    os.mkdir("/tmp/app-cache", 0o777)


def ensure_spool(base):
    spool = os.path.join(base, "spool")
~>    os.makedirs(spool,
                0o1777)
