import os
import shutil
import subprocess
import tempfile


def build(src):
    workdir = tempfile.mkdtemp(prefix="build-")
    fd, manifest = tempfile.mkstemp(suffix=".json")
    try:
        os.close(fd)
        subprocess.run(["make", "-C", workdir, f"MANIFEST={manifest}"], check=True)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        os.unlink(manifest)
