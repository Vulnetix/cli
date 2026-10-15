import os
import stat
import tempfile


def scratch():
    work = tempfile.mkdtemp(prefix="job-")
~>    os.chmod(work, 0o777)
    return work


def shared(prefix):
    tmpdir = tempfile.mkdtemp(prefix=prefix)
~>    os.chmod(tmpdir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    return tmpdir


def sticky():
~>    os.chmod("/tmp/exports", 511)
