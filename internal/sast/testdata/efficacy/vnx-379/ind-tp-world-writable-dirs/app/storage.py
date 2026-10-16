import os
import stat

UPLOAD_ROOT = os.environ.get("UPLOAD_ROOT", "/srv/uploads")


def ensure_dirs(tenant: str) -> str:
    base = os.path.join(UPLOAD_ROOT, tenant)
~>    os.makedirs(base, mode=0o777, exist_ok=True)
    spool = os.path.join(base, "spool")
    if not os.path.isdir(spool):
~>        os.mkdir(spool, 0o1777)
    return base


def ensure_shared(path):
~>    os.makedirs(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO, exist_ok=True)
