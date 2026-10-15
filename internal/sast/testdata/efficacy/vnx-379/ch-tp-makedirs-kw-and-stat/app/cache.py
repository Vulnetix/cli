import os
import stat
import tempfile

CACHE = "/var/tmp/app-cache"


def prepare():
~>    os.makedirs(CACHE, mode=0o777, exist_ok=True)
    work = tempfile.mkdtemp(prefix="job-")
~>    os.chmod(work, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
~>    os.mkdir(
        "/tmp/shared-uploads",
        0o1777,
    )
    return work
