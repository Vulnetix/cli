import os
import shutil
import subprocess
import tempfile


def run_job(script: str) -> int:
    work = tempfile.mkdtemp(prefix="job-")
    try:
        shutil.copy(script, work)
~>        os.chmod(work, 0o777)
        return subprocess.call(["runner", work])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def open_dropbox():
~>    os.chmod("/var/tmp/dropbox", 0o1777)
